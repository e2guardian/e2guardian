// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#include "../DownloadManager.hpp"
#include "../OptionContainer.hpp"
#include "../HTMLTemplate.hpp"
#include "../ConnectionHandler.hpp"

#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <cmath>
#include <cstdio>

// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;

// DECLARATIONS

class fancydm : public DMPlugin
{
    public:
    fancydm(ConfigVar &definition)
        : DMPlugin(definition), upperlimit(0), toobig_unscanned(false), toobig_notdownloaded(false){};
    int in(DataBuffer *d, Socket *sock, Socket *peersock, HTTPHeader *requestheader,
        HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig);

    int init(void *args);

    bool sendLink(Socket &peersock, String &linkurl, String &prettyurl);

    private:
    // customisable fancy DM template
    HTMLTemplate progresspage;

    // upper (non-scanned) file download size limit
    // part of "multi-stage" downloads for when content length is unknown:
    // - start downloading & hope for the best
    // - if too large, warn the user, but keep downloading (won't be scanned)
    // - if larger than upper limit also, kill download.
    off_t upperlimit;

    // was file too large to be scanned?
    bool toobig_unscanned;

    // was file so large as to not even be downloaded?
    bool toobig_notdownloaded;

    // format an integer in seconds as hours:minutes:seconds
    std::string timestring(const int seconds);
    // format a number of bytes as a number of Gb/Mb/Kb
    String bytestring(const off_t bytes);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

DMPlugin *fancydmcreate(ConfigVar &definition)
{
#ifdef DGDEBUG
    std::cout << "Creating fancy DM" << std::endl;
#endif
    return new fancydm(definition);
}

// end of Class factory

// initialisation - load the template file
int fancydm::init(void *args)
{
    // call inherited init
    DMPlugin::init(args);

    // read in absolute max download limit
    upperlimit = cv["maxdownloadsize"].toOffset() * 1024;
    if (upperlimit <= o.max_content_filecache_scan_size)
        upperlimit = 0;
#ifdef DGDEBUG
    std::cout << "Upper download limit: " << upperlimit << std::endl;
#endif

    String fname(cv["template"]);
    if (fname.length() > 0) {
        // read the template file, and return OK on success, error on failure.
        fname = o.languagepath + fname;
        return progresspage.readTemplateFile(fname.toCharArray(), "-FILENAME-|-FILESIZE-|-SERVERIP-") ? 0 : -1;
    } else {
        // eek! there's no template option in our config.
        if (!is_daemonised)
            std::cerr << "Template not specified for fancy download manager" << std::endl;
        syslog(LOG_ERR, "Template not specified for fancy download manager");
        return -2;
    }
}

// call template's downloadlink JavaScript function
bool fancydm::sendLink(Socket &peersock, String &linkurl, String &prettyurl)
{
    String mess("<script language='javascript'>\n<!--\ndownloadlink(\"" + linkurl + "\",\"" + prettyurl
        + "\"," + (toobig_notdownloaded ? "2" : (toobig_unscanned ? "1" : "0"))
        + ");\n//-->\n</script>\n");
    peersock.writeString(mess.toCharArray());
    // send text-only version for non-JS-enabled browsers
    // 1220 "Scan complete.</p><p>Click here to download: "
    // 1221 "Download complete; file not scanned.</p><p>Click here to download: "
    // 1222 "File too large to cache.</p><p>Click here to re-download, bypassing virus scanning: "
    mess = "<noscript><p>";
    mess += o.language_list.getTranslation(toobig_notdownloaded ? 1222 : (toobig_unscanned ? 1221 : 1220));
    mess += "<a href=\"" + linkurl + "\">" + prettyurl + "</a></p></noscript>";
    peersock.writeString(mess.toCharArray());
    peersock.writeString("<!-- force flush -->\r\n");
    if(!peersock.writeString("</body></html>\n")) return false;
    if (toobig_notdownloaded) {
        // add URL to clean cache (for all groups)
        addToClean(prettyurl, o.filter_groups + 1);
    }
    return true;
}

// download body for this request
int fancydm::in(DataBuffer *d, Socket *sock, Socket *peersock, class HTTPHeader *requestheader, class HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig)
{

//DataBuffer *d = where to stick the data back into
//Socket *sock = where to read from
//Socket *peersock = browser to send stuff to for keeping it alive
//HTTPHeader *docheader = header used for sending first line of reply
//HTTPHeader *requestheader = header client used to request
//bool wantall = to determine if just content filter or a full scan
//int *headersent = to use to send the first line of header if needed
//                  or to mark the header has already been sent
//bool *toobig = flag to modify to say if it could not all be downloaded

#ifdef DGDEBUG
    std::cout << "Inside fancy download manager plugin" << std::endl;
#endif

    int rc;

    off_t newsize;
    off_t expectedsize = docheader->contentLength();
    off_t bytessec = 0;
    off_t bytesgot = 0;
    int percentcomplete = 0;
    unsigned int eta = 0;
    int timeelapsed = 0;

    // if using non-persistent connections, some servers will not report
    // a content-length. in these situations, just download everything.
    bool geteverything = false;
    if ((expectedsize < 0) && !(docheader->isPersistent()))
        geteverything = true;
    if (expectedsize < 0)
        expectedsize = 0;

    bool initialsent = false;

    String message, jsmessage;

    char *block = NULL; // buffer for storing a grabbed block from the input stream
    char *temp = NULL;

    bool swappedtodisk = false;

    struct timeval starttime;
    struct timeval themdays;
    struct timeval nowadays;
    gettimeofday(&themdays, NULL);
    gettimeofday(&starttime, NULL);

    toobig_unscanned = false;
    toobig_notdownloaded = false;
    bool secondstage = false;

    // buffer size for streaming downloads
    off_t blocksize = 32768;
    // set to a sensible minimum
    if (!wantall && (blocksize > o.max_content_filter_size))
        blocksize = o.max_content_filter_size;
    else if (wantall && (blocksize > o.max_content_ramcache_scan_size))
        blocksize = o.max_content_ramcache_scan_size;
#ifdef DGDEBUG
    std::cout << "blocksize: " << blocksize << std::endl;
#endif

    // determine downloaded filename
    String filename(requestheader->disposition());
    if (filename.length() == 0) {
        filename = requestheader->getUrl();
        filename = requestheader->decode(filename);
        if (filename.contains("?"))
            filename = filename.before("?");
        while (filename.contains("/"))
            filename = filename.after("/");
    }

    while ((bytesgot < expectedsize) || geteverything) {
        // send text header to show status
        if (o.trickle_delay > 0) {
            gettimeofday(&nowadays, NULL);
            timeelapsed = nowadays.tv_sec - starttime.tv_sec;
            if ((!initialsent && timeelapsed > o.initial_trickle_delay) || (initialsent && nowadays.tv_sec - themdays.tv_sec > o.trickle_delay)) {
                initialsent = true;
                bytessec = bytesgot / timeelapsed;
                themdays.tv_sec = nowadays.tv_sec;
                if ((*headersent) < 1) {
#ifdef DGDEBUG
                    std::cout << "sending header for text status" << std::endl;
#endif
                    message = "HTTP/1.0 200 OK\nContent-Type: text/html\n\n";
                    // Output initial template
                    std::deque<String>::iterator i = progresspage.html.begin();
                    std::deque<String>::iterator penultimate = progresspage.html.end() - 1;
                    bool newline;
                    while (i != progresspage.html.end()) {
                        newline = false;
                        message = *i;
                        if (message == "-FILENAME-") {
                            message = filename;
                        } else if (message == "-FILESIZE-") {
                            message = String(expectedsize);
                        } else if (message == "-SERVERIP-") {
                            message = peersock->getLocalIP();
                        } else if ((i == penultimate) || ((*(i + 1))[0] != '-')) {
                            newline = true;
                        }
                        peersock->writeString(message.toCharArray());
                        // preserve line breaks from the original template file
                        if (newline)
                            peersock->writeString("\n");
                        i++;
                    }
                    // send please wait message for non-JS-enabled browsers
                    // 1200 "Please wait - downloading to be scanned..."
                    message = "<noscript><p>";
                    message += o.language_list.getTranslation(1200);
                    message += "</p></noscript>\n";
                    peersock->writeString(message.toCharArray());
                    (*headersent) = 2;
                }
#ifdef DGDEBUG
                std::cout << "trickle delay - sending progress..." << std::endl;
#endif
                message = "Downloading status: ";
                // Output a call to template's JavaScript progressupdate function
                jsmessage = "<script language='javascript'>\n<!--\nprogressupdate(" + String(bytesgot) + "," + String(bytessec) + ");\n//-->\n</script>";
                peersock->writeString(jsmessage.toCharArray());
                // send text only version for non-JS-enabled browsers.
                // checkme: translation?
                if (geteverything) {
                    message = "<noscript><p>Time remaining: unknown; "
                        + bytestring(bytessec) + "/s; total downloaded: " + bytestring(bytesgot) + "</p></noscript>\n";
                } else {
                    percentcomplete = bytesgot / (expectedsize / 100);
                    eta = (expectedsize - bytesgot) / bytessec;
                    message = "<noscript><p>" + String(percentcomplete) + "%, time remaining: " + timestring(eta) + "; "
                        + bytestring(bytessec) + "/s; total downloaded: " + bytestring(bytesgot) + "</p></noscript>\n";
                }
                peersock->writeString(message.toCharArray());
                peersock->writeString("<!-- force flush -->\r\n");
            }
        }

        if (wantall) {
            if (!swappedtodisk) {
                // if not swapped to disk and file is too large for RAM, then swap to disk
                if (bytesgot > o.max_content_ramcache_scan_size) {
#ifdef DGDEBUG
                    std::cout << "swapping to disk" << std::endl;
#endif
                    d->tempfilefd = d->getTempFileFD();
                    if (d->tempfilefd < 0) {
#ifdef DGDEBUG
                        std::cerr << "error buffering to disk so skipping disk buffering" << std::endl;
#endif
                        syslog(LOG_ERR, "%s", "error buffering to disk so skipping disk buffering");
                        (*toobig) = true;
                        break;
                    }
                    writeEINTR(d->tempfilefd, d->data, d->buffer_length);
                    swappedtodisk = true;
                    d->tempfilesize = d->buffer_length;
                }
            } else if (bytesgot > o.max_content_filecache_scan_size) {
                (*toobig) = true;
                toobig_unscanned = true;
                if (geteverything && (upperlimit > 0)) {
                    // multi-stage download enabled, and we don't know content length
                    if ((!secondstage) && initialsent) {
                        secondstage = true;
                        // send download size warning message
                        jsmessage = "<script language='javascript'>\n<!--\ndownloadwarning(" + String(upperlimit) + ");\n//-->\n</script>";
                        peersock->writeString(jsmessage.toCharArray());
                        // text-only version
                        message = "<noscript><p>";
                        // 1201 Warning: file too large to scan. If you suspect that this file is larger than
                        // 1202 , then refresh to download directly.
                        message += o.language_list.getTranslation(1201);
                        message += bytestring(upperlimit);
                        message += o.language_list.getTranslation(1202);
                        message += "</p></noscript>\n";
                        peersock->writeString(message.toCharArray());
                        peersock->writeString("<!-- force flush -->\r\n");
                        // add URL to clean cache (for all groups)
                        String url(requestheader->getUrl());
                        addToClean(url, o.filter_groups + 1);
#ifdef DGDEBUG
                        std::cout << "fancydm: file too big to be scanned, entering second stage of download" << std::endl;
#endif
                    }

                    // too large to even download, let alone scan
                    if (bytesgot > upperlimit) {
#ifdef DGDEBUG
                        std::cout << "fancydm: file too big to be downloaded, halting second stage of download" << std::endl;
#endif
                        toobig_unscanned = false;
                        toobig_notdownloaded = true;
                        break;
                    }
                } else {
// multi-stage download disabled, or we know content length
// if swapped to disk and file too large for that too, then give up
#ifdef DGDEBUG
                    std::cout << "fancydm: file too big to be scanned, halting download" << std::endl;
#endif
                    toobig_unscanned = false;
                    toobig_notdownloaded = true;
                    break;
                }
            }
        } else {
            if (bytesgot > o.max_content_filter_size) {
// if we aren't downloading for virus scanning, and file too large for filtering, give up
#ifdef DGDEBUG
                std::cout << "fancydm: file too big to be filtered, halting download" << std::endl;
#endif
                (*toobig) = true;
                break;
            }
        }

        if (!swappedtodisk) {
            if (d->buffer_length >= blocksize) {
                newsize = d->buffer_length;
            } else {
                newsize = blocksize;
            }
#ifdef DGDEBUG
            std::cout << "newsize: " << newsize << std::endl;
#endif
            // if not getting everything until connection close, grab only what is left
            if (!geteverything && (newsize > (expectedsize - bytesgot)))
                newsize = expectedsize - bytesgot;
            delete[] block;
            block = new char[newsize];
            try {
                if(!sock->bcheckForInput(d->timeout))
                    break;
            } catch (std::exception &e) {
                break;
            }
            // improved more efficient socket read which uses the buffer better
            rc = d->bufferReadFromSocket(sock, block, newsize, d->timeout, o.trickle_delay);
            // grab a block of input, doubled each time

            if (rc <= 0) {
                break; // an error occurred so end the while()
                // or none received so pipe is closed
            } else {
                /*if (d->data != temp)
					delete[] temp;*/
                temp = new char[d->buffer_length + rc + 1]; // replacement store
                temp[d->buffer_length + rc] = '\0';
                memcpy(temp, d->data, d->buffer_length); // copy the current data
                memcpy(temp + d->buffer_length, block, rc); // copy the new data
                delete[] d->data; // delete the current data block
                d->data = temp;
                temp = NULL;
                d->buffer_length += rc; // update data size counter
            }
        } else {
            try {
                if(!sock->bcheckForInput(d->timeout))
                    break;
            } catch (std::exception &e) {
                break;
            }
            rc = d->bufferReadFromSocket(sock, d->data,
                // if not getting everything until connection close, grab only what is left
                (!geteverything && ((expectedsize - bytesgot) < d->buffer_length) ? (expectedsize - bytesgot) : d->buffer_length), d->timeout);
            if (rc <= 0) {
                break;
            } else {
                lseek(d->tempfilefd, 0, SEEK_END); // not really needed
                writeEINTR(d->tempfilefd, d->data, rc);
                d->tempfilesize += rc;
#ifdef DGDEBUG
                std::cout << "written to disk: " << rc << " total: " << d->tempfilesize << std::endl;
#endif
            }
        }
        if (d->tempfilesize > 0) {
            bytesgot = d->tempfilesize;
        } else {
            bytesgot = d->buffer_length;
        }
    }

    if (initialsent) {

        if (!swappedtodisk) { // if we sent textual content then we can't
// stream the file to the user so we must save to disk for them
// to download by clicking on the magic link
// You can get to this point by having a large ram cache, or
// slow internet connection with small initial trickle delay.
// This should be rare.
#ifdef DGDEBUG
            std::cout << "swapping to disk" << std::endl;
#endif
            d->tempfilefd = d->getTempFileFD();
            if (d->tempfilefd < 0) {
#ifdef DGDEBUG
                std::cerr << "error buffering complete to disk so skipping disk buffering" << std::endl;
#endif
                syslog(LOG_ERR, "error buffering complete to disk so skipping disk buffering");
            } else {
                writeEINTR(d->tempfilefd, d->data, d->buffer_length);
                swappedtodisk = true;
                d->tempfilesize = d->buffer_length;
            }
        }

        // Output a call to template's JavaScript nowscanning function
        peersock->writeString("<script language='javascript'>\n<!--\nnowscanning();\n//-->\n</script>\n");
        // send text-only version
        // 1210 "Download Complete. Starting scan..."
        if (!(toobig_unscanned || toobig_notdownloaded)) {
            message = "<noscript><p>";
            message += o.language_list.getTranslation(1210);
            message += "</p></noscript>\n";
            peersock->writeString(message.toCharArray());
        }
        // only keep full downloads
        if (!toobig_notdownloaded)
            (*d).preservetemp = true;
        (*d).dontsendbody = true;
    }

    if (!(*toobig) && !swappedtodisk) { // won't deflate stuff swapped to disk
        if (d->decompress.contains("deflate")) {
#ifdef DGDEBUG
            std::cout << "zlib format" << std::endl;
#endif
            d->zlibinflate(false); // incoming stream was zlib compressed
        } else if (d->decompress.contains("gzip")) {
#ifdef DGDEBUG
            std::cout << "gzip format" << std::endl;
#endif
            d->zlibinflate(true); // incoming stream was gzip compressed
        }
    }
    d->bytesalreadysent = 0;
    /*if (d->data != temp)
		delete[] temp;*/
    delete[] block;
    return 0;
}

// format an integer in seconds as hours:minutes:seconds
std::string fancydm::timestring(const int seconds)
{
    int hours = (int)floor((double)seconds / 3600);
    int minutes = (int)floor(((double)seconds / 60) - (hours * 3600));
    int remainingseconds = seconds - (minutes * 60) - (hours * 3600);
    char result[9];
    snprintf(result, 9, "%02i:%02i:%02i", hours, minutes, remainingseconds);
    return result;
}
// format a number of bytes as a number of Gb/Mb/Kb
String fancydm::bytestring(const off_t bytes)
{
    int b = (int)floor((double)bytes / (1024 * 1024 * 1024));
    if (b > 0)
        return String(b) + " Gb";
    b = (int)floor((double)bytes / (1024 * 1024));
    if (b > 0)
        return String(b) + " Mb";
    b = (int)floor((double)bytes / 1024);
    if (b > 0)
        return String(b) + " Kb";
    return String(b) + " bytes";
}
