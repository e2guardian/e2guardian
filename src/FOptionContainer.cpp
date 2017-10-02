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
#include "ListMeta.hpp"

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
///ListMeta LMeta;

// IMPLEMENTATION

// reverse DNS lookup on IP. be aware that this can return multiple results, unlike a standard lookup.
std::deque<String> *ipToHostname(const char *ip)
{
    std::deque<String> *result = new std::deque<String>;
    struct in_addr address, **addrptr;
    if (inet_aton(ip, &address)) { // convert to in_addr
        struct hostent *answer;
        answer = gethostbyaddr((char *)&address, sizeof(address), AF_INET);
        if (answer) { // sucess in reverse dns
            result->push_back(String(answer->h_name));
            for (addrptr = (struct in_addr **)answer->h_addr_list; *addrptr; addrptr++) {
                result->push_back(String(inet_ntoa(**addrptr)));
            }
        }
    }
    return result;
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

    banned_phrase_flag = false;
    content_regexp_flag = false;
    ssl_mitm = false;

    block_downloads = false;

    banned_phrase_list_index.clear();

    //	conffile.clear();

    content_regexp_list_comp.clear();
    content_regexp_list_rep.clear();
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
// sort using startsWith or endsWith depending on sortsw,
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

bool FOptionContainer::read(const char *filename) {
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
                    temp = (char *) linebuffer.c_str();
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


        if (findoptionS("disablecontentscan") == "on") {
            disable_content_scan = true;
        } else {
            disable_content_scan = false;
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
                sslaccess_denied_domain = sslaccess_denied_domain.before(
                        "/"); // access_denied_domain now contains the FQ host nom of the
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

        // grab group name (if not using external group names file)
        if (!o.use_group_names_list) {
            name = findoptionS("groupname");
#ifdef DGDEBUG
            std::cout << "Group name: " << name << std::endl;
#endif
        }

        embedded_url_weight = findoptionI("embeddedurlweight");
#ifdef DGDEBUG
        std::cout << "Embedded URL Weight: " << embedded_url_weight << std::endl;
#endif

        category_threshold = findoptionI("categorydisplaythreshold");
#ifdef DGDEBUG
        std::cout << "Category display threshold: " << category_threshold << std::endl;
#endif




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

        std::string storyboard_location(findoptionS("storyboard"));

#ifdef DGDEBUG
        std::cout << "Read settings into memory" << std::endl;
        std::cout << "Reading phrase, URL and site lists into memory" << std::endl;
#endif

        if (!block_downloads) {
#ifdef DGDEBUG
            std::cout << "Blanket download block disabled; using standard banned file lists" << std::endl;
#endif
        }
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

        {
            std::deque<String> dq = findoptionM("ipsitelist");
#ifdef DGDEBUG
            std::cout << "ipsitelist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_IPSITE, dq)) return false;
        }

        {
        std::deque<String> dq = findoptionM("iplist");
#ifdef DGDEBUG
            std::cout << "iplist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_IP, dq)) return false;
        }

        {
        std::deque<String> dq = findoptionM("sitelist");
#ifdef DGDEBUG
            std::cout << "sitelist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_SITE, dq)) return false;
        }

        {
        std::deque<String> dq = findoptionM("urllist");
#ifdef DGDEBUG
            std::cout << "urllist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_URL, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("searchlist");
#ifdef DGDEBUG
            std::cout << "searchlist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_SEARCH, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("fileextlist");
#ifdef DGDEBUG
            std::cout << "fileextlist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_FILE_EXT, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("mimelist");
#ifdef DGDEBUG
            std::cout << "mimelist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_MIME, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("regexpboollist");
#ifdef DGDEBUG
            std::cout << "regexpboollist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_REGEXP_BOOL, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("regexpreplacelist");
#ifdef DGDEBUG
            std::cout << "regexpreplacelist deque is size " << dq.size() << std::endl;
#endif
            if(!LMeta.load_type(LIST_TYPE_REGEXP_REP, dq)) return false;
        }


#ifdef PRT_DNSAUTH
        auth_exception_url_flag = true;
#endif

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
                    if (!(exception_searchterm_list_location.length() == 0 &&
                          weighted_searchterm_list_location.length() == 0 &&
                          banned_searchterm_list_location.length() == 0)) {
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


#ifdef DGDEBUG
        std::cout << "Lists in memory" << std::endl;
#endif



    if (!StoryB.readFile(storyboard_location.c_str(), LMeta, true))
        return false;


        if(!StoryB.setEntry(ENT_STORYB_PROXY_REQUEST,"checkrequest")) {
            std::cerr << "Required storyboard entry function 'checkrequest' is missing" << std::endl;
            return false;
        }

        if(!StoryB.setEntry(ENT_STORYB_PROXY_RESPONSE,"checkresponse")) {
           std::cerr << "Required storyboard entry function 'checkresponse' is missing" << std::endl;
           return false;
        }

        if((o.transparenthttps_port > 0) && !StoryB.setEntry(ENT_STORYB_THTTPS_REQUEST,"thttps-checkrequest")) {
            std::cerr << "Required storyboard entry function 'thttps-checkrequest' is missing" << std::endl;
            return false;
        }

        if((o.icap_port > 0) && !StoryB.setEntry(ENT_STORYB_ICAP_REQMOD,"icap-checkrequest")) {
            std::cerr << "Required storyboard entry function 'icap-checkrequest' is missing" << std::endl;
            return false;
        }

            if((o.icap_port > 0) && !StoryB.setEntry(ENT_STORYB_ICAP_RESMOD,"icap-checkresponse")) {
                std::cerr << "Required storyboard entry function 'icap-checkresponse' is missing" << std::endl;
                return false;
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

std::deque<String> FOptionContainer::findoptionM(const char *option)
{
    // findoptionS returns all the matching options
    String temp;
    String temp2;
    String o(option);
    std::deque<String> results;

    for (std::deque<std::string>::iterator i = conffile.begin(); i != conffile.end(); i++) {
        if ((*i).empty())
            continue;
        temp = (*i).c_str();
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
            results.push_back(temp);
        }
    }
    return results;
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
