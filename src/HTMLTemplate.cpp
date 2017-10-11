//Implements the HTMLTemplate class, for displaying template-based banned pages to clients

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "HTMLTemplate.hpp"
#include "RegExp.hpp"
#include "String.hpp"
#include "OptionContainer.hpp"

#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <syslog.h>
//#include <istream>
#include <iostream>
#include <fstream>

// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;

// IMPLEMENTATION

// wipe the loaded template
void HTMLTemplate::reset()
{
    html.clear();
}

// push a line onto our string list
void HTMLTemplate::push(String s)
{
    if (s.length() > 0) {
        html.push_back(s);
    }
}

// read in HTML template and find URL, reason, category etc. placeholders
bool HTMLTemplate::readTemplateFile(const char *filename, const char *placeholders)
{
    std::string linebuffer;
    RegExp re;
    // compile regexp for matching supported placeholders
    // allow optional custom placeholder string
    re.comp(placeholders ? placeholders : "-URL-|-REASONGIVEN-|-REASONLOGGED-|-USER-|-IP-|-HOST-|-FILTERGROUP-|-RAWFILTERGROUP-|-BYPASS-|-CATEGORIES-|-SHORTURL-|-SERVERIP-");
    RegResult Rre;
    unsigned int offset;
    String result;
    String line;
    std::ifstream templatefile(filename, std::ios::in); // e2guardian.conf
    if (!templatefile.good()) {
        if (!is_daemonised) {
            std::cerr << "error reading: " << filename << std::endl;
        }
        syslog(LOG_ERR, "%s", "error reading HTML template file.");
        return false;
    }
    while (!templatefile.eof()) {
        std::getline(templatefile, linebuffer);
        line = linebuffer.c_str();
        // look for placeholders
        re.match(line.toCharArray(),Rre);
        while (Rre.numberOfMatches() > 0) {
            // whenever we find one, push the text before it onto the list, then the placeholder, then the text after it
            offset = Rre.offset(0);
            result = Rre.result(0).c_str();
            if (offset > 0) {
                push(line.subString(0, offset));
                push(result);
                line = line.subString(offset + result.length(), line.length() - offset - result.length());
	        if (line.length() <= 0) {
        		if (!is_daemonised) {
            			std::cerr << "Syntax error at first: " << result << std::endl;
			}
        		syslog(LOG_ERR, "Syntax error at first: %s", result.c_str());
        		return false;
        	}

            } else {
                push(result);
                line = line.subString(result.length(), line.length() - result.length());
            }
            re.match(line.toCharArray(),Rre);
        }
        // if any text remains, or we didn't find a placeholder, push the remainder of the line
        if (line.length() > 0) {
            push(line);
        }
    } 
    templatefile.close();
    return true;
}

// encode quotes and angle brackets using URL encoding to prevent XSS in the block page
void makeURLSafe(String &url)
{
    url.replaceall("'", "%27");
    url.replaceall("\"", "%22");
    url.replaceall("<", "%3C");
    url.replaceall(">", "%3E");
}

// fill in placeholders with the given information and send the resulting page to the client
// only useful if you used the default set of placeholders
void HTMLTemplate::display(Socket *s, String *url, std::string &reason, std::string &logreason, std::string &categories,
    std::string *user, std::string *ip, std::string *host, int filtergroup, String grpname, String &hashed)
{
#ifdef DGDEBUG
    std::cout << "Displaying TEMPLATE" << std::endl;
#endif
    String line;
    bool newline;
    unsigned int sz = html.size() - 1; // the last line can have no thingy. erm... carriage return?
    String safeurl(*url); // Take a copy of the URL so we can encode it to stop XSS
    bool safe = false;
    for (unsigned int i = 0; i < sz; i++) {
        // preserve newlines from original file
        newline = false;
        line = html[i];
        // look for placeholders (split onto their own line by readTemplateFile) and replace them
        if (line == "-URL-") {
            if (!safe) {
                makeURLSafe(safeurl);
                safe = true;
            }
            line = safeurl;
        } else if (line == "-SHORTURL-") {
            if (!safe) {
                makeURLSafe(safeurl);
                safe = true;
            }
            line = safeurl;
            if (line.length() > 41) {
                line = line.subString(0, 40);
                line += "...";
            }
        } else if (line == "-SERVERIP-") {
            line = s->getLocalIP();
        } else if (line == "-REASONGIVEN-") {
            String safereason = reason;
            makeURLSafe(safereason);
            line = safereason;
        } else if (line == "-REASONLOGGED-") {
            line = logreason;
        } else if (line == "-USER-") {
            String safeuser(*user);
            makeURLSafe(safeuser);
            line = safeuser;
        } else if (line == "-IP-") {
            line = *ip;
        } else if (line == "-HOST-") {
            if (host == NULL) {
#ifdef DGDEBUG
                std::cout << "-HOST- placeholder encountered but hostname currently unknown; lookup forced." << std::endl;
#endif
                std::deque<String> *names = ipToHostname(ip->c_str());
#ifdef DGDEBUG
		std::cout << "-HOST- return from ipToHostname size=" << names->size() << " Host: "<< names->front().toCharArray() << std::endl;
#endif
                if (names->size() > 0) {
                    line = names->front().toCharArray();
                } else {
		    line = "";	
		}
                delete names;
            } else {
            line = *host;
	    }
        } else if (line == "-FILTERGROUP-") {
            line = grpname;
        } else if (line == "-RAWFILTERGROUP-") {
            line = String(filtergroup + 1);
        } else if (line == "-CATEGORIES-") {
            if (categories.length() > 0) {
                line = categories;
            } else {
                line = "N/A";
            }
        } else if (line == "-BYPASS-") {
            if (hashed.length() > 0) {
                line = *url;
                if (!(url->after("://").contains("/"))) {
                    line += "/";
                }
                if (url->contains("?")) {
                    line += "&" + hashed;
                } else {
                    line += "?" + hashed;
                }
            } else {
                line = "";
            }
        } else {
            // if this line wasn't a placeholder, and neither is the
            // next line, then output a newline, thus preserving line breaks
            // from the original template file.
            if (html[i + 1][0] != '-') {
                newline = true;
            }
        }
        if (line.length() > 0) {
            s->writeString(line.toCharArray());
        }
        if (newline) {
            s->writeString("\n");
        }
    }
    s->writeString(html[sz].toCharArray());
    s->writeString("\n");
}
