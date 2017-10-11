// FOptionContainer class - contains the options for a filter group,
// including the banned/grey/exception site lists and the content/site/url regexp lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "FOptionContainer.hpp"
#include "OptionContainer.hpp"

#include <cstdlib>
#include <syslog.h>
#include <iostream>
#include <fstream>
#include <netdb.h> // for gethostby
#include <netinet/in.h> // for address structures
#include <arpa/inet.h> // for inet_aton()
#include <sys/socket.h>
//#include <unistd.h>  // remove

// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;

// IMPLEMENTATION

// reverse DNS lookup on IP. be aware that this can return multiple results, unlike a standard lookup.
std::deque<String> *ipToHostname(const char *ip)
{
    std::deque<String> *result = new std::deque<String>;
    struct in_addr address, **addrptr;
    if (inet_aton(ip, &address)) { // convert to in_addr
        struct hostent *answer;
        answer = gethostbyaddr((char *)&address, sizeof(address), AF_INET);
        if (answer) { // success in reverse dns
            result->push_back(String(answer->h_name));
            for (addrptr = (struct in_addr **)answer->h_addr_list; *addrptr; addrptr++) {
                result->push_back(String(inet_ntoa(**addrptr)));
            }
        } else {
                result->push_back(String("DNSERROR"));
		return result;
	}		
		
    }
    return result;
}

FOptionContainer::FOptionContainer()
            : block_downloads(false), searchterm_flag(false), banned_page(NULL), ssl_mitm(false),
              only_mitm_ssl_grey(false), no_check_cert_site_flag(false), ssl_check_cert(false), mitm_check_cert(true),
              referer_exception_site_flag(false), referer_exception_url_flag(false), embeded_referer_site_flag(false),
              embeded_referer_url_flag(false),
#ifdef PRT_DNSAUTH
    auth_exception_site_flag(false)
    , auth_exception_url_flag(false)
    ,   
#endif
              addheader_regexp_flag(false), banned_search_flag(false), search_regexp_flag(false),
              local_banned_search_flag(false), banned_search_overide_flag(false), local_exception_site_flag(false),
              local_exception_url_flag(false), local_banned_site_flag(false), local_banned_url_flag(false),
              local_grey_site_flag(false), local_grey_url_flag(false), enable_regex_grey(false),
              enable_local_list(false), enable_ssl_legacy_logic(false), use_only_local_allow_lists(false),
              banned_phrase_flag(false), exception_site_flag(false), exception_url_flag(false),
              banned_extension_flag(false), banned_mimetype_flag(false), banned_site_flag(false), banned_site_withbypass_flag(false),
              banned_url_flag(false), grey_site_flag(false), grey_url_flag(false), banned_regexpurl_flag(false),
              exception_regexpurl_flag(false), banned_regexpheader_flag(false), content_regexp_flag(false),
              url_regexp_flag(false), sslsite_regexp_flag(false), header_regexp_flag(false),
              url_redirect_regexp_flag(false), exception_extension_flag(false), exception_mimetype_flag(false),
              exception_file_site_flag(false), exception_file_url_flag(false), log_site_flag(false),
              log_url_flag(false), log_regexpurl_flag(false), ssl_denied_rewrite(false), reverse_lookups(false)  
{
    reset();
    reverse_lookups = o.reverse_lookups;
    force_quick_search = o.force_quick_search;
}

FOptionContainer::~FOptionContainer()
{
    reset();
}

void FOptionContainer::reset()
{
    conffile.clear();
    delete banned_page;
    banned_page = NULL;
    resetJustListData();
}

void FOptionContainer::resetJustListData()
{
    if (!(group_mode == 1))
        return;
    if (banned_phrase_flag)
        o.lm.deRefList(banned_phrase_list);
    if (searchterm_flag)
        o.lm.deRefList(searchterm_list);
    if (exception_site_flag)
        o.lm.deRefList(exception_site_list);
    if (exception_url_flag)
        o.lm.deRefList(exception_url_list);
    if (banned_extension_flag)
        o.lm.deRefList(banned_extension_list);
    if (banned_mimetype_flag)
        o.lm.deRefList(banned_mimetype_list);
    if (banned_site_flag)
        o.lm.deRefList(banned_site_list);
    if (banned_site_withbypass_flag)
        o.lm.deRefList(banned_site_list_withbypass);
    if (banned_url_flag)
        o.lm.deRefList(banned_url_list);
    if (grey_site_flag)
        o.lm.deRefList(grey_site_list);
    if (grey_url_flag)
        o.lm.deRefList(grey_url_list);
    if (banned_regexpurl_flag)
        o.lm.deRefList(banned_regexpurl_list);
    if (exception_regexpurl_flag)
        o.lm.deRefList(exception_regexpurl_list);
    if (banned_regexpheader_flag)
        o.lm.deRefList(banned_regexpheader_list);
    if (content_regexp_flag)
        o.lm.deRefList(content_regexp_list);
    if (url_regexp_flag)
        o.lm.deRefList(url_regexp_list);
    if (sslsite_regexp_flag)
        o.lm.deRefList(sslsite_regexp_list);
    if (url_redirect_regexp_flag)
        o.lm.deRefList(url_redirect_regexp_list);
    if (header_regexp_flag)
        o.lm.deRefList(header_regexp_list);
    if (exception_extension_flag)
        o.lm.deRefList(exception_extension_list);
    if (exception_mimetype_flag)
        o.lm.deRefList(exception_mimetype_list);
    if (exception_file_site_flag)
        o.lm.deRefList(exception_file_site_list);
    if (exception_file_url_flag)
        o.lm.deRefList(exception_file_url_list);
    if (log_site_flag)
        o.lm.deRefList(log_site_list);
    if (log_url_flag)
        o.lm.deRefList(log_url_list);
    if (log_regexpurl_flag)
        o.lm.deRefList(log_regexpurl_list);
//if (searchengine_regexp_flag) o.lm.deRefList(searchengine_regexp_list);
#ifdef PRT_DNSAUTH
    if (auth_exception_site_flag)
        o.lm.deRefList(auth_exception_site_list);
    if (auth_exception_url_flag)
        o.lm.deRefList(auth_exception_url_list);
#endif
    if (referer_exception_site_flag)
        o.lm.deRefList(referer_exception_site_list);
    if (referer_exception_url_flag)
        o.lm.deRefList(referer_exception_url_list);
    if (embeded_referer_site_flag)
        o.lm.deRefList(embeded_referer_site_list);
    if (embeded_referer_url_flag)
        o.lm.deRefList(embeded_referer_url_list);
    if (addheader_regexp_flag)
        o.lm.deRefList(addheader_regexp_list);
    if (banned_search_flag)
        o.lm.deRefList(banned_search_list);
    if (search_regexp_flag)
        o.lm.deRefList(search_regexp_list);
    if (enable_local_list) {
        if (local_banned_search_flag)
            o.lm.deRefList(local_banned_search_list);
        if (banned_search_overide_flag)
            o.lm.deRefList(banned_search_overide_list);
        if (local_exception_site_flag)
            o.lm.deRefList(local_exception_site_list);
        if (local_exception_url_flag)
            o.lm.deRefList(local_exception_url_list);
        if (local_banned_site_flag)
            o.lm.deRefList(local_banned_site_list);
        if (local_banned_url_flag)
            o.lm.deRefList(local_banned_url_list);
        if (local_grey_site_flag)
            o.lm.deRefList(local_grey_site_list);
        if (local_grey_url_flag)
            o.lm.deRefList(local_grey_url_list);
        if (local_banned_ssl_site_flag)
            o.lm.deRefList(local_banned_ssl_site_list);
        if (local_grey_ssl_site_flag)
            o.lm.deRefList(local_grey_ssl_site_list);
    }

#ifdef __SSLMITM
    if (no_check_cert_site_flag)
        o.lm.deRefList(no_check_cert_site_list);
#endif

    if (banned_ssl_site_flag)
        o.lm.deRefList(banned_ssl_site_list);
    if (grey_ssl_site_flag)
        o.lm.deRefList(grey_ssl_site_list);
    banned_phrase_flag = false;
    searchterm_flag = false;
    exception_site_flag = false;
    exception_url_flag = false;
    banned_extension_flag = false;
    banned_mimetype_flag = false;
    banned_site_flag = false;
    banned_site_withbypass_flag = false;
    banned_url_flag = false;
    grey_site_flag = false;
    grey_url_flag = false;
    banned_regexpurl_flag = false;
    exception_regexpurl_flag = false;
    banned_regexpheader_flag = false;
    content_regexp_flag = false;
    url_regexp_flag = false;
    sslsite_regexp_flag = false;
    url_redirect_regexp_flag = false;
    header_regexp_flag = false;
    exception_extension_flag = false;
    exception_mimetype_flag = false;
    exception_file_site_flag = false;
    exception_file_url_flag = false;
    log_site_flag = false;
    log_url_flag = false;
    log_regexpurl_flag = false;
    enable_local_list = false;
    enable_regex_grey = false;
    only_mitm_ssl_grey = false;
    ssl_mitm = false;
    enable_ssl_legacy_logic = false;
//searchengine_regexp_flag = false;
#ifdef PRT_DNSAUTH
    auth_exception_site_flag = false;
    auth_exception_url_flag = false;
#endif
    referer_exception_site_flag = false;
    referer_exception_url_flag = false;
    embeded_referer_site_flag = false;
    embeded_referer_url_flag = false;
    use_only_local_allow_lists = false;
    local_exception_site_flag = false;
    local_exception_url_flag = false;
    local_banned_site_flag = false;
    local_banned_url_flag = false;
    local_grey_site_flag = false;
    local_grey_url_flag = false;
    local_banned_ssl_site_flag = false;
    local_grey_ssl_site_flag = false;
    addheader_regexp_flag = false;
    addheader_regexp_list_comp.clear();
    addheader_regexp_list_rep.clear();
    banned_search_flag = false;
    search_regexp_flag = false;
    search_regexp_list_comp.clear();
    search_regexp_list_rep.clear();
    local_banned_search_flag = false;
    banned_search_overide_flag = false;
    banned_ssl_site_flag = false;
    grey_ssl_site_flag = false;

#ifdef __SSLMITM
    no_check_cert_site_flag = false;
#endif

    block_downloads = false;

    banned_phrase_list_index.clear();

    //	conffile.clear();

    content_regexp_list_comp.clear();
    content_regexp_list_rep.clear();
    url_regexp_list_comp.clear();
    url_regexp_list_rep.clear();
    sslsite_regexp_list_comp.clear();
    sslsite_regexp_list_rep.clear();
    url_redirect_regexp_list_comp.clear();
    url_redirect_regexp_list_rep.clear();
    header_regexp_list_comp.clear();
    header_regexp_list_rep.clear();
    banned_regexpurl_list_comp.clear();
    banned_regexpurl_list_source.clear();
    banned_regexpurl_list_ref.clear();
    exception_regexpurl_list_comp.clear();
    exception_regexpurl_list_source.clear();
    exception_regexpurl_list_ref.clear();
    banned_regexpheader_list_comp.clear();
    banned_regexpheader_list_source.clear();
    banned_regexpheader_list_ref.clear();
    log_regexpurl_list_comp.clear();
    log_regexpurl_list_source.clear();
    log_regexpurl_list_ref.clear();
    //searchengine_regexp_list_comp.clear();
    //searchengine_regexp_list_source.clear();
    //searchengine_regexp_list_ref.clear();

    //	delete banned_page;
    //	banned_page = NULL;
}

// grab this FG's HTML template
// TODO must be removed ?
HTMLTemplate *FOptionContainer::getHTMLTemplate()
{
    if (banned_page)
        return banned_page;
    return &(o.html_template);
}

// read in the given file, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw, and create a cache file if desired.
// listname is used in error messages.
bool FOptionContainer::readFile(const char *filename, unsigned int *whichlist, bool sortsw, bool cache, const char *listname)
{
    if (strlen(filename) < 3) {
        if (!is_daemonised) {
            std::cerr << "Required Listname " << listname << " is not defined" << std::endl;
        }
        syslog(LOG_ERR, "Required Listname %s is not defined", listname);
        return false;
    }
    int res = o.lm.newItemList(filename, sortsw, 1, true);
    if (res < 0) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    (*whichlist) = (unsigned)res;
    if (!(*o.lm.l[(*whichlist)]).used) {
        if (sortsw)
            (*o.lm.l[(*whichlist)]).doSort(true);
        else
            (*o.lm.l[(*whichlist)]).doSort(false);
        (*o.lm.l[(*whichlist)]).used = true;
    }
#ifdef DGDEBUG
    std::cout << "Blanket flags are **:*ip:**s:**sip = " << (*o.lm.l[(*whichlist)]).blanketblock << ":" << (*o.lm.l[(*whichlist)]).blanket_ip_block << ":" << (*o.lm.l[(*whichlist)]).blanketsslblock << ":" << (*o.lm.l[(*whichlist)]).blanketssl_ip_block << std::endl;
#endif
    return true;
}

bool FOptionContainer::read(const char *filename)
{
    try { // all sorts of exceptions could occur reading conf files
        std::string linebuffer;
        String temp; // for tempory conversion and storage
        std::ifstream conffiles(filename, std::ios::in); // e2guardianfN.conf
        if (!conffiles.good()) {
            if (!is_daemonised) {
                std::cerr << "Error reading: " << filename << std::endl;
            }
            syslog(LOG_ERR, "Error reading %s", filename);
            return false;
        }
        while (!conffiles.eof()) {
            getline(conffiles, linebuffer);
            if (!conffiles.eof() && linebuffer.length() != 0) {
                if (linebuffer[0] != '#') { // i.e. not commented out
                    temp = (char *)linebuffer.c_str();
                    if (temp.contains("#")) {
                        temp = temp.before("#");
                    }
                    temp.removeWhiteSpace(); // get rid of spaces at end of line
                    linebuffer = temp.toCharArray();
                    conffile.push_back(linebuffer); // stick option in deque
                }
            }
        }
        conffiles.close();

#ifdef DGDEBUG
        std::cout << "Read conf into memory: " << filename << std::endl;
#endif

        if (findoptionS("deepurlanalysis") == "on") {
            deep_url_analysis = true;
        } else {
            deep_url_analysis = false;
        }

        if (findoptionS("disablecontentscan") == "on") {
            disable_content_scan = true;
        } else {
            disable_content_scan = false;
        }

        if (findoptionS("disablecontentscanerror") == "on") {
            disable_content_scan_error = true;
        } else {
            disable_content_scan_error = false;
        }


        if (findoptionS("useonlylocalallowlists") == "on") {
            use_only_local_allow_lists = true;
        } else {
            use_only_local_allow_lists = false;
        }

        String mimes = findoptionS("textmimetypes");
        if (mimes != "") {
            size_t comma = mimes.find(',');
            while (comma != std::string::npos) {
              text_mime.push_back(mimes.substr(0, comma));
              mimes = mimes.substr(comma + 1);
              comma = mimes.find(',');
             }
              text_mime.push_back(mimes.substr(0, comma));
              mimes = mimes.substr(comma + 1);
#ifdef DGDEBUG
              int size = (int) text_mime.size();
	      int i;
	      for (i = 0; i < size; i++) {
                    std::cout << "mimes filtering : " << text_mime[i] << std::endl;
              }
#endif
        }

        if (findoptionS("ssllegacylogic") == "on") {
            enable_ssl_legacy_logic = true;
        } else {
            enable_ssl_legacy_logic = false;
        }

#ifdef __SSLMITM
        if (findoptionS("sslcheckcert") == "on") {
            if(o.enable_ssl) {
                ssl_check_cert = true;
                } else {
                syslog(LOG_ERR, "Warning: To use sslcheckcert, enablessl in e2guardian.conf must be on");
                std::cout << "Warning: sslcheckcert requires ssl to be enabled in e2guardian.conf " << std::endl;
                ssl_check_cert = false;
                }
        } else {
            ssl_check_cert = false;
        }
#endif //__SSLCERT

#ifdef __SSLMITM
        if (findoptionS("sslmitm") == "on") {
            if(o.enable_ssl) {
                ssl_mitm = true;
                if (findoptionS("onlymitmsslgrey") == "on") {
                    only_mitm_ssl_grey = true;
                } else {
                    only_mitm_ssl_grey = false;
                }
                if (enable_ssl_legacy_logic) {
                    syslog(LOG_ERR, "Warning: sslmitm requires ssllegacylogic to be off");
                    std::cout << "Warning: sslmitm requires ssllegacylogic to be off" << std::endl;
                    enable_ssl_legacy_logic = false;
                }

                if (findoptionS("mitmcheckcert") == "off")
                    mitm_check_cert = false;

                allow_empty_host_certs = false;
                if (findoptionS("allowemptyhostcert") == "on")
                    allow_empty_host_certs = true;
            } else {
                syslog(LOG_ERR, "Warning: To use sslmitm, enablessl in e2guardian.conf must be on");
                std::cout << "Warning: sslmitm requires ssl to be enabled in e2guardian.conf " << std::endl;
                ssl_mitm = false;
            }
        } else {
            ssl_mitm = false;
        }
#endif //__SSLMITM

#ifdef ENABLE_EMAIL
        // Email notification patch by J. Gauthier
        if (findoptionS("usesmtp") == "on") {
            use_smtp = true;
        } else {
            use_smtp = false;
        }

        if (findoptionS("thresholdbyuser") == "on") {
            byuser = true;
        } else {
            byuser = false;
        }

        if (findoptionS("notifyav") == "on") {
            if (!use_smtp) {
                if (!is_daemonised)
                    std::cerr << "notifyav cannot be on while usesmtp is off." << std::endl;
                syslog(LOG_ERR, "notifyav cannot be on while usesmtp is off.");
                return false;
            }
            notifyav = true;
        } else {
            notifyav = false;
        }

        if (findoptionS("notifycontent") == "on") {
            if (!use_smtp) {
                if (!is_daemonised)
                    std::cerr << "notifycontent cannot be on while usesmtp is off." << std::endl;
                syslog(LOG_ERR, "notifycontent cannot be on while usesmtp is off.");
                return false;
            }
            notifycontent = true;
        } else {
            notifycontent = false;
        }

        violations = findoptionI("violations");
        current_violations = 0;
        violationbody = "";

        threshold = findoptionI("threshold");

        avadmin = findoptionS("avadmin");
        if (avadmin.length() == 0) {
            if (notifyav == 1) {
                if (!is_daemonised)
                    std::cerr << "avadmin cannot be blank while notifyav is on." << std::endl;
                syslog(LOG_ERR, "avadmin cannot be blank while notifyav is on.");
                return false;
            }
        }

        contentadmin = findoptionS("contentadmin");
        if (contentadmin.length() == 0) {
            if (use_smtp) {
                if (!is_daemonised)
                    std::cerr << "contentadmin cannot be blank while usesmtp is on." << std::endl;
                syslog(LOG_ERR, "contentadmin cannot be blank while usesmtp is on.");
                return false;
            }
        }

        mailfrom = findoptionS("mailfrom");
        if (mailfrom.length() == 0) {
            if (use_smtp) {
                if (!is_daemonised)
                    std::cerr << "mailfrom cannot be blank while usesmtp is on." << std::endl;
                syslog(LOG_ERR, "mailfrom cannot be blank while usesmtp is on.");
                return false;
            }
        }
        avsubject = findoptionS("avsubject");
        if (avsubject.length() == 0 && notifyav == 1 && use_smtp == 1) {
            if (!is_daemonised)
                std::cerr << "avsubject cannot be blank while notifyav is on." << std::endl;
            syslog(LOG_ERR, "avsubject cannot be blank while notifyav is on.");
            return false;
        }

        contentsubject = findoptionS("contentsubject");
        if (contentsubject.length() == 0 && use_smtp) {
            if (!is_daemonised)
                std::cerr << "contentsubject cannot be blank while usesmtp is on." << std::endl;
            syslog(LOG_ERR, "contentsubject cannot be blank while usesmtp is on.");
            return false;
        }

#endif
        // override default reporting level
        reporting_level = findoptionI("reportinglevel");
        if (!realitycheck(reporting_level, -1, 3, "reportinglevel")) {
            return false;
        }

        if (reporting_level == 0) {
            std::cerr << "Reporting_level is : " << reporting_level << " file " << filename << std::endl;
            syslog(LOG_ERR, "Reporting_level is : %d file %s", reporting_level, filename);
        }

        long temp_max_upload_size;
        temp_max_upload_size = findoptionI("maxuploadsize");

        if ((realitycheck(temp_max_upload_size, -1, 10000000, "max_uploadsize")) && (temp_max_upload_size != 0)) {
            max_upload_size = temp_max_upload_size;
            if (temp_max_upload_size > 0)
                max_upload_size *= 1024;
        } else {
            if (!is_daemonised)
                std::cerr << "Invalid maxuploadsize: " << temp_max_upload_size << std::endl;
            syslog(LOG_ERR, "Invalid maxuploadsize: %ld", temp_max_upload_size);
            return false;
        }

#ifdef DGDEBUG
        std::cout << "Group " << findoptionS("groupname") << "(" << filtergroup << ") Max upload size in e2guardian group file: " << temp_max_upload_size << std::endl;
#endif
        // override default access denied address
        if (reporting_level == 1 || reporting_level == 2) {
            String temp_ada, temp_add;
            temp_ada = findoptionS("accessdeniedaddress");
            if (temp_ada != "") {
                access_denied_address = temp_ada.toCharArray();
                access_denied_domain = access_denied_address.c_str();
                access_denied_domain = access_denied_domain.after("://");
                access_denied_domain.removeWhiteSpace();
                if (access_denied_domain.contains("/")) {
                    access_denied_domain = access_denied_domain.before("/");
                    // access_denied_domain now contains the FQ host name of the
                    // server that serves the accessdenied.html file
                }
                if (access_denied_domain.contains(":")) {
                    access_denied_domain = access_denied_domain.before(":"); // chop off the port number if any
                }
            } else {
                access_denied_domain = "localhost"; // No initialized value
                if (access_denied_domain.length() < 4) {
                    if (!is_daemonised) {
                        std::cerr << "Warning accessdeniedaddress setting appears to be wrong." << std::endl;
                    }
                    syslog(LOG_ERR, "%s", "Warning accessdeniedaddress setting appears to be wrong.");
                }
            }
        }
        if (reporting_level == 3) {
            // override default banned page
            String html_template(findoptionS("htmltemplate"));
            if (html_template != "") {
                html_template = o.languagepath + html_template;
                banned_page = new HTMLTemplate;
                if (!(banned_page->readTemplateFile(html_template.toCharArray()))) {
                    if (!is_daemonised) {
                        std::cerr << "Error reading HTML Template file: " << html_template << std::endl;
                    }
                    syslog(LOG_ERR, "Error reading HTML Template file: %s", html_template.toCharArray());
                    return false;
                    // HTML template file
                }
            } else {
                html_template = o.languagepath + "template.html";
                banned_page = new HTMLTemplate;
                if (!(banned_page->readTemplateFile(html_template.toCharArray()))) {
                    if (!is_daemonised) {
                        std::cerr << "Error reading default HTML Template file: " << html_template << std::endl;
                    }
                    syslog(LOG_ERR, "Error reading default HTML Template file: %s", html_template.toCharArray());
                    return false;
                    // HTML template file
                }
            }
        }
        // override ssl default banned page
        sslaccess_denied_address = findoptionS("sslaccessdeniedaddress");
        if ((sslaccess_denied_address.length() != 0)) {
            sslaccess_denied_domain = sslaccess_denied_address.c_str();
            sslaccess_denied_domain = sslaccess_denied_domain.after("://");
            sslaccess_denied_domain.removeWhiteSpace();
            if (sslaccess_denied_domain.contains("/")) {
                sslaccess_denied_domain = sslaccess_denied_domain.before("/"); // access_denied_domain now contains the FQ host nom of the
                // server that serves the accessdenied.html file
            }
            if (sslaccess_denied_domain.contains(":")) {
                sslaccess_denied_domain = sslaccess_denied_domain.before(":"); // chop off the port number if any
            }

            if (sslaccess_denied_domain.length() < 4) {
                if (!is_daemonised) {
                    std::cerr << " sslaccessdeniedaddress setting appears to be wrong." << std::endl;
                }
                syslog(LOG_ERR, "%s", " sslaccessdeniedaddress setting appears to be wrong.");
                return false;
            }
            if (findoptionS("ssldeniedrewrite") == "on") {
                ssl_denied_rewrite = true;
            } else {
                ssl_denied_rewrite = false;
            }
        }

        if (findoptionS("nonstandarddelimiter") == "off") {
            non_standard_delimiter = false;
        } else {
            non_standard_delimiter = true;
        }

	// TODE Remove groupemode CODE
        // group mode: 0 = banned, 1 = filtered, 2 = exception
        group_mode = 1;
        if ((group_mode < 0) || (group_mode > 2)) {
            if (!is_daemonised)
                std::cerr << "Invalid groupmode" << std::endl;
            syslog(LOG_ERR, "Invalid groupmode");
            return false;
        }
#ifdef DGDEBUG
        std::cout << "Group mode: " << group_mode << std::endl;
#endif

        // grab group name (if not using external group names file)
        if (!o.use_group_names_list) {
            name = findoptionS("groupname");
#ifdef DGDEBUG
            std::cout << "Group name: " << name << std::endl;
#endif
        }

        if (group_mode == 1) {

            embedded_url_weight = findoptionI("embeddedurlweight");
#ifdef DGDEBUG
            std::cout << "Embedded URL Weight: " << embedded_url_weight << std::endl;
#endif

            category_threshold = findoptionI("categorydisplaythreshold");
#ifdef DGDEBUG
            std::cout << "Category display threshold: " << category_threshold << std::endl;
#endif

            // the e2guardian.conf and pics files get amalgamated into one
            // deque.  They are only separate files for clarity.

//            if (findoptionS("enablepics") == "on") {
                //.enable_PICS = true;
            //} else {
                enable_PICS = false;
            //}

            if (findoptionS("ssllegacylogic") == "on") {
                enable_ssl_legacy_logic = true;
            } else {
                enable_ssl_legacy_logic = false;
            }

            if (findoptionS("bannedregexwithblanketblock") == "on") {
                enable_regex_grey = true;
            } else {
                enable_regex_grey = false;
            }

            if (findoptionS("enablelocallists") == "on") {
                enable_local_list = true;
            } else {
                enable_local_list = false;
            }

            if (findoptionS("blockdownloads") == "on") {
                block_downloads = true;
            } else {
                block_downloads = false;
            }


            // Support weighted phrase mode per group
            if (findoptionS("weightedphrasemode").length() > 0) {
                weighted_phrase_mode = findoptionI("weightedphrasemode");
                if (!realitycheck(weighted_phrase_mode, 0, 3, "weightedphrasemode"))
                    return false;
            }

            std::string exception_phrase_list_location(findoptionS("exceptionphraselist"));
            std::string weighted_phrase_list_location(findoptionS("weightedphraselist"));
            std::string banned_phrase_list_location(findoptionS("bannedphraselist"));
            std::string banned_extension_list_location(findoptionS("bannedextensionlist"));
            std::string banned_mimetype_list_location(findoptionS("bannedmimetypelist"));
            std::string banned_site_list_location(findoptionS("bannedsitelist"));
	    std::string banned_site_list_withbypass_location(findoptionS("bannedsitelistwithbypass"));
            std::string banned_url_list_location(findoptionS("bannedurllist"));
            std::string grey_site_list_location(findoptionS("greysitelist"));
            std::string grey_url_list_location(findoptionS("greyurllist"));
            std::string banned_regexpurl_list_location(findoptionS("bannedregexpurllist"));
            std::string exception_regexpurl_list_location(findoptionS("exceptionregexpurllist"));
            std::string banned_regexpheader_list_location(findoptionS("bannedregexpheaderlist"));
            std::string content_regexp_list_location(findoptionS("contentregexplist"));
            std::string url_regexp_list_location(findoptionS("urlregexplist"));
            std::string sslsite_regexp_list_location(findoptionS("sslsiteregexplist"));
            std::string header_regexp_list_location(findoptionS("headerregexplist"));
            std::string exceptions_site_list_location(findoptionS("exceptionsitelist"));
            std::string exceptions_url_list_location(findoptionS("exceptionurllist"));
            std::string exception_extension_list_location(findoptionS("exceptionextensionlist"));
            std::string exception_mimetype_list_location(findoptionS("exceptionmimetypelist"));
            std::string exception_file_site_list_location(findoptionS("exceptionfilesitelist"));
            std::string exception_file_url_list_location(findoptionS("exceptionfileurllist"));
            std::string log_url_list_location(findoptionS("logurllist"));
            std::string log_site_list_location(findoptionS("logsitelist"));
            std::string log_regexpurl_list_location(findoptionS("logregexpurllist"));

            // search term blocking
            std::string searchengine_regexp_list_location(findoptionS("searchengineregexplist"));

#ifdef PRT_DNSAUTH
            std::string auth_exceptions_site_list_location(findoptionS("authexceptionsitelist"));
            std::string auth_exceptions_url_list_location(findoptionS("authexceptionurllist"));
#endif
            std::string url_redirect_regexp_list_location(findoptionS("urlredirectregexplist"));
            std::string referer_exceptions_site_list_location(findoptionS("refererexceptionsitelist"));
            std::string referer_exceptions_url_list_location(findoptionS("refererexceptionurllist"));
            std::string embeded_referer_site_list_location(findoptionS("embededreferersitelist"));
            std::string embeded_referer_url_list_location(findoptionS("embededrefererurllist"));
            std::string addheader_regexp_list_location(findoptionS("addheaderregexplist"));
            std::string banned_search_list_location(findoptionS("bannedsearchlist"));
            std::string search_regexp_list_location(findoptionS("searchregexplist"));
            std::string local_banned_search_list_location(findoptionS("localbannedsearchlist"));
            std::string banned_search_overide_list_location(findoptionS("bannedsearchoveridelist"));
            std::string local_banned_site_list_location(findoptionS("localbannedsitelist"));
            std::string local_banned_url_list_location(findoptionS("localbannedurllist"));
            std::string local_grey_site_list_location(findoptionS("localgreysitelist"));
            std::string local_grey_url_list_location(findoptionS("localgreyurllist"));
            std::string local_exceptions_site_list_location(findoptionS("localexceptionsitelist"));
            std::string local_exceptions_url_list_location(findoptionS("localexceptionurllist"));
            std::string local_banned_ssl_site_list_location(findoptionS("localbannedsslsitelist"));
            std::string local_grey_ssl_site_list_location(findoptionS("localgreysslsitelist"));

            std::string banned_ssl_site_list_location(findoptionS("bannedsslsitelist"));
            std::string grey_ssl_site_list_location(findoptionS("greysslsitelist"));
#ifdef __SSLMITM
            std::string no_check_cert_site_list_location(findoptionS("nocheckcertsitelist"));
#endif

#ifdef DGDEBUG
            std::cout << "Read settings into memory" << std::endl;
            std::cout << "Reading phrase, URL and site lists into memory" << std::endl;
#endif

            if (!block_downloads) {
#ifdef DGDEBUG
                std::cout << "Blanket download block disabled; using standard banned file lists" << std::endl;
#endif
                if (!readFile(banned_extension_list_location.c_str(), &banned_extension_list, false, false, "bannedextensionlist")) {
                    return false;
                } // file extensions
                banned_extension_flag = true;
                if (!readFile(banned_mimetype_list_location.c_str(), &banned_mimetype_list, false, true, "bannedmimetypelist")) {
                    return false;
                } // mime types
                banned_mimetype_flag = true;
            }
            if (!readFile(exception_extension_list_location.c_str(), &exception_extension_list, false, false, "exceptionextensionlist")) {
                return false;
            } // file extensions
            exception_extension_flag = true;
            if (!readFile(exception_mimetype_list_location.c_str(), &exception_mimetype_list, false, true, "exceptionmimetypelist")) {
                return false;
            } // mime types
            exception_mimetype_flag = true;
            if (!readFile(exception_file_site_list_location.c_str(), &exception_file_site_list, false, true, "exceptionfilesitelist")) {
                return false;
            } // download site exceptions
            exception_file_site_flag = true;
            if (!readFile(exception_file_url_list_location.c_str(), &exception_file_url_list, true, true, "exceptionfileurllist")) {
                return false;
            } // download site exceptions
            exception_file_url_flag = true;

            if (weighted_phrase_mode > 0) {
                naughtyness_limit = findoptionI("naughtynesslimit");
                if (!realitycheck(naughtyness_limit, 1, 0, "naughtynesslimit"))
                    return false;

                if (!o.lm.readbplfile(banned_phrase_list_location.c_str(),
                        exception_phrase_list_location.c_str(),
                        weighted_phrase_list_location.c_str(), banned_phrase_list,
                        force_quick_search)) {
                    return false;
                } // read banned, exception, weighted phrase list
                banned_phrase_flag = true;
            }

            if (!readFile(exceptions_site_list_location.c_str(), &exception_site_list, false, true, "exceptionsitelist")) {
                return false;
            } // site exceptions
            exception_site_flag = true;
            if (!readFile(exceptions_url_list_location.c_str(), &exception_url_list, true, true, "exceptionurllist")) {
                return false;
            } // url exceptions
            exception_url_flag = true;
            if (!readFile(banned_site_list_location.c_str(), &banned_site_list, false, true, "bannedsitelist")) {
                return false;
            } // banned domains
            banned_site_flag = true;
            if (!readFile(banned_site_list_withbypass_location.c_str(), &banned_site_list_withbypass, false, true, "bannedsitelistwithbypass")) {
                 return false;
            } // banned domains
            banned_site_withbypass_flag = true;
            if (!readFile(banned_url_list_location.c_str(), &banned_url_list, true, true, "bannedurllist")) {
                return false;
            } // banned urls
            banned_url_flag = true;
            if (!readFile(grey_site_list_location.c_str(), &grey_site_list, false, true, "greysitelist")) {
                return false;
            } // grey domains
            grey_site_flag = true;
            if (!readFile(grey_url_list_location.c_str(), &grey_url_list, true, true, "greyurllist")) {
                return false;
            } // grey urls
            grey_url_flag = true;

#ifdef PRT_DNSAUTH
            if (!readFile(auth_exceptions_site_list_location.c_str(), &auth_exception_site_list, false, true, "authexceptionsitelist")) {
                return false;
            } // non_auth site exceptions
            auth_exception_site_flag = true;
            if (!readFile(auth_exceptions_url_list_location.c_str(), &auth_exception_url_list, true, true, "authexceptionurllist")) {
                return false;
            } // non-auth url exceptions
            auth_exception_url_flag = true;
#endif
            if (referer_exceptions_site_list_location.length() && readFile(referer_exceptions_site_list_location.c_str(), &referer_exception_site_list, false, true, "refererexceptionsitelist")) {
                referer_exception_site_flag = true;
            } else { // referer site exceptions
                referer_exception_site_flag = false;
            }

            if (referer_exceptions_url_list_location.length() && readFile(referer_exceptions_url_list_location.c_str(), &referer_exception_url_list, true, true, "refererexceptionurllist")) {
                referer_exception_url_flag = true;
            } else { // referer url exceptions
                referer_exception_url_flag = false;
            }

            if (embeded_referer_site_list_location.length() && readFile(embeded_referer_site_list_location.c_str(), &embeded_referer_site_list, false, true, "embededreferersitelist")) {
                embeded_referer_site_flag = true;
            } else { // referer site exceptions
                embeded_referer_site_flag = false;
            }

            if (embeded_referer_url_list_location.length() && readFile(embeded_referer_url_list_location.c_str(), &embeded_referer_url_list, true, true, "embededrefererurllist")) {
                embeded_referer_url_flag = true;
            } else { // referer url exceptions
                embeded_referer_url_flag = false;
            }

            if (addheader_regexp_list_location.length() && readRegExReplacementFile(addheader_regexp_list_location.c_str(), "addheaderregexplist", addheader_regexp_list, addheader_regexp_list_rep, addheader_regexp_list_comp)) {
                addheader_regexp_flag = true;
            } else { // url regular expressions for header insertions
                addheader_regexp_flag = false;
            }

            if (searchengine_regexp_list_location.length()) {
                if (!is_daemonised) {
                    std::cerr << "Error: searchengineregexplist is no longer supported. Please use searchregexplist instead. " << std::endl;
                }
                syslog(LOG_ERR, "Error: searchengineregexplist is no longer supported. Please use searchregexplist instead.");
                return false;
            }

            if (banned_search_list_location.length() && readFile(banned_search_list_location.c_str(), &banned_search_list, true, true, "bannedsearchlist")) {
                banned_search_flag = true;
            } else {
                banned_search_flag = false;
            } // banned search words

            if (search_regexp_list_location.length() && readRegExReplacementFile(search_regexp_list_location.c_str(), "searchregexplist", search_regexp_list, search_regexp_list_rep, search_regexp_list_comp)) {
                search_regexp_flag = true;
#ifdef DGDEBUG
                std::cout << "Enabled search term extraction RegExp list" << std::endl;
#endif
            } else {
                search_regexp_flag = false;
            } // search engine searchwords regular expressions

            // local list
            if (enable_local_list) {
                if (local_banned_search_list_location.length() && readFile(local_banned_search_list_location.c_str(), &local_banned_search_list, true, true, "localbannedsearchlist")) {
                    local_banned_search_flag = true;
                } else {
                    local_banned_search_flag = false;
                } // local banned search words

                if (banned_search_overide_list_location.length() && readFile(banned_search_overide_list_location.c_str(), &banned_search_overide_list, true, true, "bannedsearchoveridelist")) {
                    banned_search_overide_flag = true;
                } else {
                    banned_search_overide_flag = false;
                } // banned search overide words

                if (!readFile(local_exceptions_site_list_location.c_str(), &local_exception_site_list, false, true, "localexceptionsitelist")) {
                    return false;
                } // site exceptions
                local_exception_site_flag = true;
                if (!readFile(local_exceptions_url_list_location.c_str(), &local_exception_url_list, true, true, "localexceptionurllist")) {
                    return false;
                } // url exceptions
                local_exception_url_flag = true;
                if (!readFile(local_banned_site_list_location.c_str(), &local_banned_site_list, false, true, "localbannedsitelist")) {
                    return false;
                } // banned domains
                local_banned_site_flag = true;
                if (!readFile(local_banned_url_list_location.c_str(), &local_banned_url_list, true, true, "localbannedurllist")) {
                    return false;
                } // banned urls
                local_banned_url_flag = true;
                if (!readFile(local_grey_site_list_location.c_str(), &local_grey_site_list, false, true, "localgreysitelist")) {
                    return false;
                } // grey domains
                local_grey_site_flag = true;
                if (!readFile(local_grey_url_list_location.c_str(), &local_grey_url_list, true, true, "localgreyurllist")) {
                    return false;
                } // grey urls
                local_grey_url_flag = true;

                if (local_banned_ssl_site_list_location.length() && readFile(local_banned_ssl_site_list_location.c_str(), &local_banned_ssl_site_list, false, true, "localbannedsslsitelist")) {
                    local_banned_ssl_site_flag = true;
                } else { // banned domains
                    local_banned_ssl_site_flag = false;
                }
                if (local_grey_ssl_site_list_location.length() && readFile(local_grey_ssl_site_list_location.c_str(), &local_grey_ssl_site_list, false, true, "localgreysslsitelist")) {
                    local_grey_ssl_site_flag = true;
                } else { // grey domains
                    local_grey_ssl_site_flag = false;
                }
            }

            if (banned_ssl_site_list_location.length() && readFile(banned_ssl_site_list_location.c_str(), &banned_ssl_site_list, false, true, "bannedsslsitelist")) {
                banned_ssl_site_flag = true;
            } else { // banned domains
                banned_ssl_site_flag = false;
            }

            if (grey_ssl_site_list_location.length() && readFile(grey_ssl_site_list_location.c_str(), &grey_ssl_site_list, false, true, "greysslsitelist")) {
                grey_ssl_site_flag = true;
            } else {
                if (only_mitm_ssl_grey) {
                    syslog(LOG_ERR, "onlymitmsslgrey requires greysslsitelist");
                    std::cout << "onlymitmsslgrey requires greysslsitelist" << std::endl;
                    return false;
                } else {
                    grey_ssl_site_flag = false;
                }
            }
#ifdef __SSLMITM
            if (mitm_check_cert && no_check_cert_site_list_location.length() && readFile(no_check_cert_site_list_location.c_str(), &no_check_cert_site_list, false, true, "nocheckcertsitelist")) {
                no_check_cert_site_flag = true;
            } // do not check certs for these sites
            else {
                no_check_cert_site_flag = false;
            }
#endif
            // log-only lists
            if (log_url_list_location.length() && readFile(log_url_list_location.c_str(), &log_url_list, true, true, "logurllist")) {
                log_url_flag = true;
#ifdef DGDEBUG
                std::cout << "Enabled log-only URL list" << std::endl;
#endif
            } else {
                log_url_flag = false;
            }

            if (log_site_list_location.length() && readFile(log_site_list_location.c_str(), &log_site_list, false, true, "logsitelist")) {
                log_site_flag = true;
#ifdef DGDEBUG
                std::cout << "Enabled log-only domain list" << std::endl;
#endif
            } else {
                log_site_flag = false;
            }

            if (log_regexpurl_list_location.length() && readRegExMatchFile(log_regexpurl_list_location.c_str(), "logregexpurllist", log_regexpurl_list,
                                                            log_regexpurl_list_comp, log_regexpurl_list_source, log_regexpurl_list_ref)) {
                log_regexpurl_flag = true;
#ifdef DGDEBUG
                std::cout << "Enabled log-only RegExp URL list" << std::endl;
#endif
            } else {
                log_regexpurl_flag = false;
            }
            // search term blocking
            //			if (searchengine_regexp_list_location.length() && readRegExMatchFile(searchengine_regexp_list_location.c_str(), "searchengineregexplist", searchengine_regexp_list,
            //				searchengine_regexp_list_comp, searchengine_regexp_list_source, searchengine_regexp_list_ref))
            if (search_regexp_flag) {
                if (weighted_phrase_mode > 0) {
                    searchterm_limit = findoptionI("searchtermlimit");
                    if (!realitycheck(searchterm_limit, 0, 0, "searchtermlimit")) {
                        return false;
                    }

                    // Optionally override the normal phrase lists for search term blocking.
                    // We need all three lists to build a phrase tree, so fail if we encounter
                    // anything other than all three enabled/disabled simultaneously.
                    if (searchterm_limit > 0) {
                        std::string exception_searchterm_list_location(findoptionS("exceptionsearchtermlist"));
                        std::string weighted_searchterm_list_location(findoptionS("weightedsearchtermlist"));
                        std::string banned_searchterm_list_location(findoptionS("bannedsearchtermlist"));
                        if (!(exception_searchterm_list_location.length() == 0 && weighted_searchterm_list_location.length() == 0 && banned_searchterm_list_location.length() == 0)) {
                            // At least one is enabled - try to load all three.
                            if (!o.lm.readbplfile(banned_searchterm_list_location.c_str(),
                                    exception_searchterm_list_location.c_str(),
                                    weighted_searchterm_list_location.c_str(), searchterm_list,
                                    force_quick_search)) {
                                return false;
                            }
                            searchterm_flag = true;
                        }
                    }
                }
            }

            if (!readRegExMatchFile(banned_regexpurl_list_location.c_str(), "bannedregexpurllist", banned_regexpurl_list,
                    banned_regexpurl_list_comp, banned_regexpurl_list_source, banned_regexpurl_list_ref)) {
                return false;
            } // banned reg exp urls
            banned_regexpurl_flag = true;

            if (!readRegExMatchFile(exception_regexpurl_list_location.c_str(), "exceptionregexpurllist", exception_regexpurl_list,
                    exception_regexpurl_list_comp, exception_regexpurl_list_source, exception_regexpurl_list_ref)) {
                return false;
            } // exception reg exp urls
            exception_regexpurl_flag = true;

            if (!readRegExMatchFile(banned_regexpheader_list_location.c_str(), "bannedregexpheaderlist", banned_regexpheader_list,
                    banned_regexpheader_list_comp, banned_regexpheader_list_source, banned_regexpheader_list_ref)) {
                return false;
            } // banned reg exp headers
            banned_regexpheader_flag = true;

            if (!readRegExReplacementFile(content_regexp_list_location.c_str(), "contentregexplist", content_regexp_list, content_regexp_list_rep, content_regexp_list_comp)) {
                return false;
            } // content replacement regular expressions
            content_regexp_flag = true;

            if (!readRegExReplacementFile(url_regexp_list_location.c_str(), "urlregexplist", url_regexp_list, url_regexp_list_rep, url_regexp_list_comp)) {
                return false;
            } // url replacement regular expressions
            url_regexp_flag = true;

            if (!readRegExReplacementFile(sslsite_regexp_list_location.c_str(), "sslsiteregexplist", sslsite_regexp_list, sslsite_regexp_list_rep, sslsite_regexp_list_comp)) {
                return false;
            } // url replacement regular expressions
            sslsite_regexp_flag = true;

            if (!readRegExReplacementFile(header_regexp_list_location.c_str(), "headerregexplist", header_regexp_list, header_regexp_list_rep, header_regexp_list_comp)) {
                return false;
            } // header replacement regular expressions
            header_regexp_flag = true;

            if (url_redirect_regexp_list_location.length() && readRegExReplacementFile(url_redirect_regexp_list_location.c_str(), "urlredirectregexplist", url_redirect_regexp_list, url_redirect_regexp_list_rep, url_redirect_regexp_list_comp)) {
                url_redirect_regexp_flag = true;
            } // url redirect expressions

#ifdef DGDEBUG
            std::cout << "Lists in memory" << std::endl;
#endif
        }

        if (!precompileregexps()) {
            return false;
        } // precompiled reg exps for speed

        //
        //
        // Bypass/infection bypass modes
        //
        //

        bypass_mode = findoptionI("bypass");
        if (!realitycheck(bypass_mode, -1, 0, "bypass")) {
            return false;
        }
        // we use the "magic" key here both for filter bypass *and* for filter bypass after virus scan (fancy DM).
        if ((bypass_mode != 0) || (disable_content_scan != 1)) {
            magic = findoptionS("bypasskey");
            if (magic.length() < 9) {
                std::string s(16u, ' ');
                for (int i = 0; i < 16; i++) {
                    s[i] = (rand() % 26) + 'A';
                }
                magic = s;
            }
#ifdef DGDEBUG
            std::cout << "Setting magic key to '" << magic << "'" << std::endl;
#endif
            // Create the Bypass Cookie magic key
            cookie_magic = std::string(16u, ' ');
            for (int i = 0; i < 16; i++) {
                cookie_magic[i] = (rand() % 26) + 'A';
            }
        }

        infection_bypass_mode = findoptionI("infectionbypass");
        if (!realitycheck(infection_bypass_mode, -1, 0, "infectionbypass")) {
            return false;
        }
        if (infection_bypass_mode != 0) {
            imagic = findoptionS("infectionbypasskey");
            if (imagic.length() < 9) {
                std::string s(16u, ' ');
                for (int i = 0; i < 16; i++) {
                    s[i] = (rand() % 26) + 'A';
                }
                imagic = s;
            }
#ifdef DGDEBUG
            std::cout << "Setting imagic key to '" << imagic << "'" << std::endl;
#endif
            if (findoptionS("infectionbypasserrorsonly") == "off") {
                infection_bypass_errors_only = false;
            } else {
#ifdef DGDEBUG
                std::cout << "Only allowing infection bypass on scan error" << std::endl;
#endif
                infection_bypass_errors_only = true;
            }
        }
    } catch (std::exception &e) {
        if (!is_daemonised) {
            std::cerr << e.what() << std::endl; // when called the daemon has not
            // detached so we can do this
        }
        return false;
    }
    return true;
}

// read regexp url list
bool FOptionContainer::readRegExMatchFile(const char *filename, const char *listname, unsigned int &listref,
    std::deque<RegExp> &list_comp, std::deque<String> &list_source, std::deque<unsigned int> &list_ref)
{
    int result = o.lm.newItemList(filename, true, 32, true);
    if (result < 0) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    listref = (unsigned)result;
    return compileRegExMatchFile(listref, list_comp, list_source, list_ref);
}

// NOTE TO SELF - MOVE TO LISTCONTAINER TO SOLVE FUDGE
// compile regexp url list
bool FOptionContainer::compileRegExMatchFile(unsigned int list, std::deque<RegExp> &list_comp,
    std::deque<String> &list_source, std::deque<unsigned int> &list_ref)
{
    for (unsigned int i = 0; i < (*o.lm.l[list]).morelists.size(); i++) {
        if (!compileRegExMatchFile((*o.lm.l[list]).morelists[i], list_comp, list_source, list_ref)) {
            return false;
        }
    }
    RegExp r;
    bool rv = true;
    int len = (*o.lm.l[list]).getListLength();
    String source;
    for (int i = 0; i < len; i++) {
        source = (*o.lm.l[list]).getItemAtInt(i).c_str();
        rv = r.comp(source.toCharArray());
        if (rv == false) {
            if (!is_daemonised) {
                std::cerr << "Error compiling regexp:" << source << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error compiling regexp:");
            syslog(LOG_ERR, "%s", source.toCharArray());
            return false;
        }
        list_comp.push_back(r);
        list_source.push_back(source);
        list_ref.push_back(list);
    }
    (*o.lm.l[list]).used = true;
    return true;
}

// content and URL regular expression replacement files
bool FOptionContainer::readRegExReplacementFile(const char *filename, const char *listname, unsigned int &listid,
    std::deque<String> &list_rep, std::deque<RegExp> &list_comp)
{
    int result = o.lm.newItemList(filename, true, 32, true);
    if (result < 0) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    listid = (unsigned)result;
    if (!(*o.lm.l[listid]).used) {
        //(*o.lm.l[listid]).doSort(true);
        (*o.lm.l[listid]).used = true;
    }
    RegExp r;
    bool rv = true;
    String regexp;
    String replacement;
    for (int i = 0; i < (*o.lm.l[listid]).getListLength(); i++) {
        regexp = (*o.lm.l[listid]).getItemAtInt(i).c_str();
        replacement = regexp.after("\"->\"");
        while (!replacement.endsWith("\"")) {
            if (replacement.length() < 2) {
                break;
            }
            replacement.chop();
        }
        replacement.chop();
        regexp = regexp.after("\"").before("\"->\"");
        //        if (replacement.length() < 1 || regexp.length() < 1) {
        if (regexp.length() < 1) { // allow replace with nothing
            continue;
        }
        rv = r.comp(regexp.toCharArray());
        if (rv == false) {
            if (!is_daemonised) {
                std::cerr << "Error compiling regexp: " << (*o.lm.l[listid]).getItemAtInt(i) << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error compiling regexp: ");
            syslog(LOG_ERR, "%s", (*o.lm.l[listid]).getItemAtInt(i).c_str());
            return false;
        }
        list_comp.push_back(r);
        list_rep.push_back(replacement);
    }
    return true;
}

// Recursively check site & URL lists for blanket matches
char *FOptionContainer::testBlanketBlock(unsigned int list, bool ip, bool ssl, String &lastcategory)
{
    if (not o.lm.l[list]->isNow())
        return NULL;
#ifdef DGDEBUG
    std::cout << "Blanket flags are **:*ip:**s:**sip = " << o.lm.l[list]->blanketblock << ":" << o.lm.l[list]->blanket_ip_block << ":" << o.lm.l[list]->blanketsslblock << ":" << o.lm.l[list]->blanketssl_ip_block << std::endl;
#endif
    if (o.lm.l[list]->blanketblock) {
        lastcategory = "-";
        return (char *)o.language_list.getTranslation(502);
    } else if (o.lm.l[list]->blanket_ip_block and ip) {
        lastcategory = "IP";
        return (char *)o.language_list.getTranslation(505);
    } else if (o.lm.l[list]->blanketsslblock and ssl) {
        lastcategory = "HTTPS";
        return (char *)o.language_list.getTranslation(506);
    } else if (o.lm.l[list]->blanketssl_ip_block and ssl and ip) {
        lastcategory = "HTTPS_IP";
        return (char *)o.language_list.getTranslation(507);
    }
    /* # Disable recursive to reduce wasted CPU and fix wrong lastcategory issue PIP
	for (std::vector<int>::iterator i = o.lm.l[list]->morelists.begin(); i != o.lm.l[list]->morelists.end(); i++) {
		char *r = testBlanketBlock(*i, ip, ssl);
		if (r) {
			return r;
		}
	}
*/
    return NULL;
}

// checkme: there's an awful lot of removing whitespace, PTP, etc. going on here.
// perhaps connectionhandler could keep a suitably modified version handy to prevent repitition of work?

char *FOptionContainer::inSiteList(String &url, unsigned int list, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
    // Perform blanket matching if desired
    if (doblanket) {
        char *r = testBlanketBlock(list, ip, ssl, lastcategory);
        if (r) {
            return r;
        }
    }

    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        url = url.before("/"); // chop off any path after the domain
    }
    char *i;
    bool isipurl = isIPHostname(url);
    if (reverse_lookups && isipurl) { // change that ip into hostname
        std::deque<String> *url2s = ipToHostname(url.toCharArray());
        String url2;
        for (std::deque<String>::iterator j = url2s->begin(); j != url2s->end(); j++) {
            url2 = *j;
            while (url2.contains(".")) {
                i = (*o.lm.l[list]).findInList(url2.toCharArray(), lastcategory);
                if (i != NULL) {
                    delete url2s;
                    return i; // exact match
                }
                url2 = url2.after("."); // check for being in hld
            }
        }
        delete url2s;
    }
    while (url.contains(".")) {
        i = (*o.lm.l[list]).findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
        url = url.after("."); // check for being in higher level domains
    }
    if (url.length() > 1) { // allows matching of .tld
        url = "." + url;
        i = (*o.lm.l[list]).findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
    }
    return NULL; // and our survey said "UUHH UURRGHH"
}

char *FOptionContainer::inSearchList(String &words, unsigned int list, String &lastcategory)
{
    char *i = (*o.lm.l[list]).findInList(words.toCharArray(), lastcategory);
    if (i != NULL) {
        return i; // exact match
    }
    return NULL;
}

// checkme: remove things like this & make inSiteList/inIPList public?

char *FOptionContainer::inBannedSiteList(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inBannedSiteList check: doblanket = " << doblanket << " ssl = " << ssl << std::endl;
#endif
    return inSiteList(url, banned_site_list, doblanket, ip, ssl, lastcategory);
}

char *FOptionContainer::inBannedSiteListwithbypass(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inBannedSiteListwithbypass check: doblanket = " << doblanket << " ssl = " << ssl << " url = " << url <<  " lastcategory = " << lastcategory << std::endl;
#endif
    return inSiteList(url, banned_site_list_withbypass, doblanket, ip, ssl, lastcategory);
}


bool FOptionContainer::inGreySiteList(String url, bool doblanket, bool ip, bool ssl)
{
    //	if (enable_local_list) {
    if (use_only_local_allow_lists) {
        return false;
    };
    //	}
    if (ssl && !enable_ssl_legacy_logic) {
        return inGreySSLSiteList(url, doblanket, ip, ssl);
    };
    String lastcategory;
    return inSiteList(url, grey_site_list, doblanket, ip, ssl, lastcategory) != NULL;
}

char *FOptionContainer::inBannedSSLSiteList(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
    if (banned_ssl_site_flag) {
        return inSiteList(url, banned_ssl_site_list, doblanket, ip, ssl, lastcategory);
    } else {
        return NULL;
    }
}

bool FOptionContainer::inGreySSLSiteList(String url, bool doblanket, bool ip, bool ssl)
{
    if (grey_ssl_site_flag) {
        String lastcat;
        return inSiteList(url, grey_ssl_site_list, doblanket, ip, ssl, lastcat) != NULL;
    } else {
        return false;
    }
}

bool FOptionContainer::inNoCheckCertSiteList(String url, bool ip)
{
    if (no_check_cert_site_flag) {
        String lastcat;
        return inSiteList(url, no_check_cert_site_list, false, ip, true, lastcat) != NULL;
    } else {
        return false;
    }
}
#ifdef PRT_DNSAUTH
bool FOptionContainer::inAuthExceptionSiteList(String url, bool doblanket, bool ip, bool ssl)
{
    String lc;
    return inSiteList(url, auth_exception_site_list, doblanket, ip, ssl,lc) != NULL;
}
#endif

bool FOptionContainer::inRefererExceptionLists(String url)
{
    String temp = url;
    String lc;
    if ((url.length() > 0)
        && ((referer_exception_site_flag && (inSiteList(url, referer_exception_site_list, false, false, false,lc) != NULL))
               || (referer_exception_url_flag && (inURLList(temp, referer_exception_url_list, false, false, false, lc) != NULL))))
        return true;
    return false;
}

bool FOptionContainer::inEmbededRefererLists(String url)
{
    String temp = url;
    String lc;
    if ((url.length() > 0)
        && ((embeded_referer_site_flag && (inSiteList(url, embeded_referer_site_list, false, false, false, lc) != NULL))
               || (embeded_referer_url_flag && (inURLList(temp, embeded_referer_url_list, false, false, false, lc) != NULL))))
        return true;
    return false;
}

char *FOptionContainer::inBannedSearchList(String words, String &lc)
{

#ifdef DGDEBUG
    std::cout << "Checking Banned Search Overide list for " << words << std::endl;
#endif
    if (enable_local_list) {
        if (inBannedSearchOverideList(words))
            return NULL;
    }
#ifdef DGDEBUG
    std::cout << "Checking Banned Search list for " << words << std::endl;
#endif
    return inSearchList(words, banned_search_list, lc);
}

char *FOptionContainer::inLocalBannedSearchList(String words, String &lc)
{
#ifdef DGDEBUG
    std::cout << "Checking Local Banned Search list for " << words << std::endl;
#endif
    return inSearchList(words, local_banned_search_list, lc);
}
bool FOptionContainer::inBannedSearchOverideList(String words)
{
    String lc;
#ifdef DGDEBUG
    std::cout << "Checking Banned Search Overide list for " << words << std::endl;
#endif
    return inSearchList(words, banned_search_overide_list, lc) != NULL;
}

bool FOptionContainer::inLocalExceptionSiteList(String url, bool doblanket, bool ip, bool ssl, String &lc)
{
#ifdef DGDEBUG
    std::cout << "inLocalExceptionSiteList" << std::endl;
#endif
    return inSiteList(url, local_exception_site_list, doblanket, ip, ssl, lc) != NULL;
}

char *FOptionContainer::inLocalBannedSiteList(String url, bool doblanket, bool ip, bool ssl, String &lc)
{
#ifdef DGDEBUG
    std::cout << "inLocalBannedSiteList" << std::endl;
#endif
    return inSiteList(url, local_banned_site_list, doblanket, ip, ssl, lc);
}

bool FOptionContainer::inLocalGreySiteList(String url, bool doblanket, bool ip, bool ssl)
{
    String lc;
    if (ssl) {
        return inSiteList(url, local_grey_ssl_site_list, doblanket, ip, ssl, lc) != NULL;
    };
    return inSiteList(url, local_grey_site_list, doblanket, ip, ssl, lc) != NULL;
}

char *FOptionContainer::inLocalBannedSSLSiteList(String url, bool doblanket, bool ip, bool ssl, String &lc)
{
    return inSiteList(url, local_banned_ssl_site_list, doblanket, ip, ssl, lc);
}

bool FOptionContainer::inLocalGreySSLSiteList(String url, bool doblanket, bool ip, bool ssl)
{
    String lc;
    return inSiteList(url, local_grey_ssl_site_list, doblanket, ip, ssl, lc) != NULL;
}

bool FOptionContainer::inExceptionSiteList(String url, bool doblanket, bool ip, bool ssl, String &lc)
{
    return inSiteList(url, exception_site_list, doblanket, ip, ssl, lc) != NULL;
}

bool FOptionContainer::inExceptionFileSiteList(String url)
{
    String lc;
    if (inSiteList(url, exception_file_site_list, false, false, false, lc) != NULL)
        return true;
    else
        return inURLList(url, exception_file_url_list, false, false, false, lc) != NULL;
}

// look in given URL list for given URL
char *FOptionContainer::inURLList(String &url, unsigned int list, bool doblanket, bool ip, bool ssl, String &lc)
{
    if (ssl) { // can't be in url list as SSL is site only
        return NULL;
    };
    // Perform blanket matching if desired
    if (doblanket) {
        char *r = testBlanketBlock(list, ip, ssl, lc);
        if (r) {
            return r;
        }
    }

    unsigned int fl;
    char *i;
    String foundurl;
#ifdef DGDEBUG
    std::cout << "inURLList: " << url << std::endl;
#endif
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        String tpath("/");
        tpath += url.after("/");
        url = url.before("/");
        tpath.hexDecode();
        tpath.realPath();
        url += tpath; // will resolve ../ and %2e2e/ and // etc
    }
    if (url.endsWith("/")) {
        url.chop(); // chop off trailing / if any
    }
#ifdef DGDEBUG
    std::cout << "inURLList (processed): " << url << std::endl;
#endif
    if (reverse_lookups && url.after("/").length() > 0) {
        String hostname(url.getHostname());
        if (isIPHostname(hostname)) {
            std::deque<String> *url2s = ipToHostname(hostname.toCharArray());
            String url2;
            for (std::deque<String>::iterator j = url2s->begin(); j != url2s->end(); j++) {
                url2 = *j;
                url2 += "/";
                url2 += url.after("/");
                while (url2.before("/").contains(".")) {
                    i = (*o.lm.l[list]).findStartsWith(url2.toCharArray(),lc);
                    if (i != NULL) {
                        foundurl = i;
                        fl = foundurl.length();
                        if (url2.length() > fl) {
                            unsigned char c = url[fl];
                            if (c == '/' || c == '?' || c == '&' || c == '=') {
                                delete url2s;
                                return i; // matches /blah/ or /blah/foo
                                // (or /blah?foo etc.)
                                // but not /blahfoo
                            }
                        } else {
                            delete url2s;
                            return i; // exact match
                        }
                    }
                    url2 = url2.after("."); // check for being in hld
                }
            }
            delete url2s;
        }
    }
    while (url.before("/").contains(".")) {
        i = (*o.lm.l[list]).findStartsWith(url.toCharArray(),lc);
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
#ifdef DGDEBUG
            std::cout << "foundurl: " << foundurl << foundurl.length() << std::endl;
            std::cout << "url: " << url << fl << std::endl;
#endif
            if (url.length() > fl) {
                if (url[fl] == '/' || url[fl] == '?' || url[fl] == '&' || url[fl] == '=') {
                    return i; // matches /blah/ or /blah/foo but not /blahfoo
                }
            } else {
                return i; // exact match
            }
        }
        url = url.after("."); // check for being in higher level domains
    }
    return NULL;
}

char *FOptionContainer::inBannedURLList(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inBannedURLList" << std::endl;
#endif
    return inURLList(url, banned_url_list, doblanket, ip, ssl, lastcategory);
}

bool FOptionContainer::inGreyURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
    std::cout << "inGreyURLList" << std::endl;
#endif
    if (enable_local_list) {
        if (use_only_local_allow_lists) {
            return false;
        };
    };
    String lastcategory;
    return inURLList(url, grey_url_list, doblanket, ip, ssl, lastcategory) != NULL;
}

bool FOptionContainer::inExceptionURLList(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inExceptionURLList" << std::endl;
#endif
    return inURLList(url, exception_url_list, doblanket, ip, ssl, lastcategory) != NULL;
}

char *FOptionContainer::inLocalBannedURLList(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inLocalBannedURLList" << std::endl;
#endif
    return inURLList(url, local_banned_url_list, doblanket, ip, ssl, lastcategory);
}

bool FOptionContainer::inLocalGreyURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
    std::cout << "inLocalGreyURLList" << std::endl;
#endif
    String lastcategory;
    return inURLList(url, local_grey_url_list, doblanket, ip, ssl, lastcategory) != NULL;
}

bool FOptionContainer::inLocalExceptionURLList(String url, bool doblanket, bool ip, bool ssl, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inLocalExceptionURLList" << std::endl;
#endif
    return inURLList(url, local_exception_url_list, doblanket, ip, ssl, lastcategory) != NULL;
}

#ifdef PRT_DNSAUTH
bool FOptionContainer::inAuthExceptionURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
    std::cout << "inAuthExceptionURLList" << std::endl;
#endif
    String lc;
    return inURLList(url, auth_exception_url_list, doblanket, ip, ssl, lc) != NULL;
}
#endif

// New log-only site lists
const char *FOptionContainer::inLogURLList(String url, String &lastcategory)
{
    if (!log_url_flag)
        return NULL;
    if (inURLList(url, log_url_list, false, false, false, lastcategory) != NULL) {
        return lastcategory.toCharArray();
    }
    return NULL;
}

const char *FOptionContainer::inLogSiteList(String url, String &lastcategory)
{
    if (!log_site_flag)
        return NULL;
    if (inSiteList(url, log_site_list, false, false, false, lastcategory) != NULL) {
        return lastcategory.toCharArray();
    }
    return NULL;
}

const char *FOptionContainer::inLogRegExpURLList(String url)
{
    if (!log_regexpurl_flag)
        return NULL;
    String lc;
    int j = inRegExpURLList(url, log_regexpurl_list_comp, log_regexpurl_list_ref, log_regexpurl_list, lc);
    if (j == -1)
        return NULL;
    return o.lm.l[log_regexpurl_list_ref[j]]->category.toCharArray();
}

// TODO: Store the modified URL somewhere, instead of re-processing it every time.

char *FOptionContainer::inExtensionList(unsigned int list, String url)
{
    String lc;
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.hexDecode();
    url.removePTP(); // chop off the ht(f)tp(s)://
    url = url.after("/"); // chop off any domain before the path
    if (url.length() < 2) { // will never match
        return NULL;
    }
    return (*o.lm.l[list]).findEndsWith(url.toCharArray(), lc);
}

// replaced by HTTPHeader::isSearch function in e2g so undefined but
// retained for reference.
#ifdef NOTDEFINED
// search term blocking
// is this URL recognised by the search engine regexp list?  if so, return extracted search terms
bool FOptionContainer::extractSearchTerms(String url, String &terms)
{
    if (!searchengine_regexp_flag)
        return false;

    url.removeWhiteSpace();
    url.removePTP();

#ifdef DGDEBUG
    std::cout << "extractSearchTerms: " << url << std::endl;
#endif
    unsigned int i = 0;
    // iterate over all regexes in the compiled list.  if the source list is enabled
    // at the current time, test to see if the regex itself matches the URL.
    for (std::deque<RegExp>::iterator j = searchengine_regexp_list_comp.begin(); j != searchengine_regexp_list_comp.end(); j++) {
        if (o.lm.l[searchengine_regexp_list_ref[i]]->isNow()) {
            j->match(url.toCharArray());
            if (j->matched()) {
                // return the first submatch.
                // if there are no submatches, the regex isn't suitable for
                // actually extracting search terms; treat this as an error.
                // match 1 is the whole string matched by the regex - we need
                // at least 2 matches for there to have been a submatch.
                if (j->numberOfMatches() < 2) {
#ifdef DGDEBUG
                    std::cout << "extractSearchTerms: matched a regex with no submatches: " << searchengine_regexp_list_source[i] << std::endl;
#endif
                    syslog(LOG_ERR, "extractSearchTerms: no submatches in regex! (%s)", searchengine_regexp_list_source[i].toCharArray());
                    return false;
                }
                terms = j->result(1);
                // change '+' to ' ' then hex decode (remove URL parameter encoding)
                terms.replaceall("+", " ");
                terms.hexDecode();
                // also replace any characters which could potentially screw up logging
                terms.replaceall("\t", " ");
                terms.replaceall(",", " ");
                terms.replaceall(";", " ");
#ifdef DGDEBUG
                std::cout << "extractSearchTerms: matched something: " << searchengine_regexp_list_source[i] << ", " << terms << std::endl;
#endif
                return true;
            }
        }
        ++i;
    }
    return false;
}
#endif

// is this line of the headers in the banned regexp header list?
int FOptionContainer::inBannedRegExpHeaderList(std::deque<String> &header, String &lastcategory)
{
     RegResult Rre;
    for (std::deque<String>::iterator k = header.begin(); k != header.end(); k++) {
#ifdef DGDEBUG
        std::cout << "inBannedRegExpHeaderList: " << *k << std::endl;
#endif
        unsigned int i = 0;
        for (std::deque<RegExp>::iterator j = banned_regexpheader_list_comp.begin(); j != banned_regexpheader_list_comp.end(); j++) {
            if (o.lm.l[banned_regexpheader_list_ref[i]]->isNow()) {
                if(j->match(k->toCharArray(),Rre))
                    return i;
            }
#ifdef DGDEBUG
            else
                std::cout << "Outside included regexp list's time limit" << std::endl;
#endif
            i++;
        }
    }
    return -1;
}

// is this URL in the given regexp URL list?
int FOptionContainer::inRegExpURLList(String &url, std::deque<RegExp> &list_comp, std::deque<unsigned int> &list_ref, unsigned int list, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inRegExpURLList: " << url << std::endl;
#endif
    // check parent list's time limit
    if (o.lm.l[list]->isNow()) {
        RegResult Rre;
        url.removeWhiteSpace(); // just in case of weird browser crap
        url.toLower();
        // chop off the PTP (ht(f)tp(s)://)
        /*String ptp;
		if (url.contains("//")) {
			ptp = url.before("//");
			url = url.after("//");
		}*/

        // whilst it would be nice to have regexes be able to match the PTP,
        // it has been assumed for too long that the URL string does not start with one,
        // and we don't want to break regexes that look explicitly for the start of
        // the string. changes here have therefore been reverted. 2005-12-07
        url.removePTP();
        if (url.contains("/")) {
            String tpath("/");
            tpath += url.after("/");
            url = url.before("/");
            tpath.hexDecode();
            tpath.realPath();
            url += tpath; // will resolve ../ and %2e2e/ and // etc
        }
        if (url.endsWith("/")) {
            url.chop(); // chop off trailing / if any
        }
// re-add the PTP
/*if (ptp.length() > 0)
			url = ptp + "//" + url;*/
#ifdef DGDEBUG
        std::cout << "inRegExpURLList (processed): " << url << std::endl;
#endif
        unsigned int i = 0;
        for (std::deque<RegExp>::iterator j = list_comp.begin(); j != list_comp.end(); j++) {
            if (o.lm.l[list_ref[i]]->isNow()) {
                if(j->match(url.toCharArray(),Rre))
                    return i;
            }
#ifdef DGDEBUG
            else
                std::cout << "Outside included regexp list's time limit" << std::endl;
#endif
            i++;
        }
    }
#ifdef DGDEBUG
    else {
        std::cout << "Outside top level regexp list's time limit" << std::endl;
    }
#endif
    return -1;
}

// use above to check banned/exception RegExp URLs
int FOptionContainer::inBannedRegExpURLList(String url, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inBannedRegExpURLList" << std::endl;
#endif
    return inRegExpURLList(url, banned_regexpurl_list_comp, banned_regexpurl_list_ref, banned_regexpurl_list, lastcategory);
}

int FOptionContainer::inExceptionRegExpURLList(String url, String &lastcategory)
{
#ifdef DGDEBUG
    std::cout << "inExceptionRegExpURLList" << std::endl;
#endif
    return inRegExpURLList(url, exception_regexpurl_list_comp, exception_regexpurl_list_ref, exception_regexpurl_list, lastcategory);
}

bool FOptionContainer::isIPHostname(String url)
{
    RegResult Rre;
    if (!isiphost.match(url.toCharArray(),Rre)) {
        return true;
    }
    return false;
}

int FOptionContainer::findoptionI(const char *option)
{
    int res = String(findoptionS(option).c_str()).toInteger();
    return res;
}

std::string FOptionContainer::findoptionS(const char *option)
{
    // findoptionS returns a found option stored in the deque
    String temp;
    String temp2;
    String o(option);
    for (int i = 0; i < (signed)conffile.size(); i++) {
        temp = conffile[i].c_str();
        temp2 = temp.before("=");
        while (temp2.endsWith(" ")) { // get rid of tailing spaces before =
            temp2.chop();
        }
        if (o == temp2) {
            temp = temp.after("=");
            while (temp.startsWith(" ")) { // get rid of heading spaces
                temp.lop();
            }
            if (temp.startsWith("'")) { // inverted commas
                temp.lop();
            }
            while (temp.endsWith(" ")) { // get rid of tailing spaces
                temp.chop();
            }
            if (temp.endsWith("'")) { // inverted commas
                temp.chop();
            }
            return temp.toCharArray();
        }
    }
    return "";
}

bool FOptionContainer::realitycheck(int l, int minl, int maxl, const char *emessage)
{
    // realitycheck checks a String for certain expected criteria
    // so we can spot problems in the conf files easier
    if ((l < minl) || ((maxl > 0) && (l > maxl))) {
        if (!is_daemonised) {
            // when called we have not detached from
            // the console so we can write back an
            // error

            std::cerr << "Config problem; check allowed values for " << emessage << std::endl;
        }
        syslog(LOG_ERR, "Config problem; check allowed values for %s", emessage);

        return false;
    }
    return true;
}

bool FOptionContainer::precompileregexps()
{
    if (!isiphost.comp(".*[a-z|A-Z].*")) {
        if (!is_daemonised) {
            std::cerr << "Error compiling RegExp isiphost." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Error compiling RegExp isiphost.");
        return false;
    }

    return true;
}

bool FOptionContainer::isOurWebserver(String url)
{
    // reporting levels 0 and 3 don't use the CGI
    if (reporting_level == 1 || reporting_level == 2) {
        url.removeWhiteSpace(); // just in case of weird browser crap
        url.toLower();
        url.removePTP(); // chop off the ht(f)tp(s)://
        if (url.contains("/")) {
            url = url.before("/"); // chop off any path after the domain
        }
        if (url.startsWith(access_denied_domain)) { // don't filter our web server
            return true;
        }
    }
    return false;
}
