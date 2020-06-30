// FOptionContainer class - contains the options for a filter group,
// including the banned/grey/exception site lists and the content/site/url regexp lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "FOptionContainer.hpp"
#include "OptionContainer.hpp"
#include "ListMeta.hpp"
#include "Logger.hpp"

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
extern thread_local std::string thread_id;

///ListMeta LMeta;

// IMPLEMENTATION

// reverse DNS lookup on IP. be aware that this can return multiple results, unlike a standard lookup.
std::deque<String> *ipToHostname(const char *ip)
{
    std::deque<String> *result = new std::deque<String>;
    //struct in_addr address, **addrptr;
    struct in_addr address;
    if (inet_aton(ip, &address)) { // convert to in_addr
        struct hostent *answer;
        answer = gethostbyaddr((char *)&address, sizeof(address), AF_INET);
        if (answer) { // success in reverse dns
            result->push_back(String(answer->h_name));
        }
    }
    return result;
}

void getClientFromIP(const char *ip, std::string &clienthost)
{
    std::unique_ptr<std::deque<String> > hostnames;
    hostnames.reset(ipToHostname(ip));
    if(hostnames->empty()) {
        clienthost = ip;
    } else {
        clienthost = std::string(hostnames->front().toCharArray());
    }
}

FOptionContainer::~FOptionContainer()
{
    reset();
}

void FOptionContainer::reset()
{
    conffile.clear();
    if (neterr_page != nullptr)
    {
        delete neterr_page;
        neterr_page = nullptr;
    }
    if (banned_page != nullptr) {
        delete banned_page;
        banned_page = nullptr;
    }
    resetJustListData();
}

void FOptionContainer::resetJustListData()
{
    if (banned_phrase_flag)
        o.lm.deRefList(banned_phrase_list);

    banned_phrase_flag = false;
    content_regexp_flag = false;
    ssl_mitm = false;

    banned_phrase_list_index.clear();

    //	conffile.clear();

    content_regexp_list_comp.clear();
    content_regexp_list_rep.clear();
}

// grab this FG's HTML template
HTMLTemplate *FOptionContainer::getHTMLTemplate(bool upfail)
{
    if(upfail && neterr_page)
        return neterr_page;
    if (banned_page)
        return banned_page;
    return &(o.html_template);
}


// read in the given file, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw,
// listname is used in error messages.
bool FOptionContainer::readFile(const char *filename, const char *list_pwd, unsigned int *whichlist, bool sortsw, bool cache, const char *listname)
{
    logger_trace(filename);
    if (strlen(filename) < 3) {
        logger_error("Required Listname ", listname, " is not defined");
        return false;
    }
    int res = o.lm.newItemList(filename, list_pwd, sortsw, 1, true);
    if (res < 0) {
        logger_error("Error opening ", listname);
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
    return true;
}

bool FOptionContainer::readConfFile(const char *filename, String &list_pwd) {
    logger_trace(filename);    
    std::string linebuffer;
    String now_pwd(list_pwd);
    String temp; // for tempory conversion and storage
    std::ifstream conffiles(filename, std::ios::in); // e2guardianfN.conf

    if (!conffiles.good()) {
        logger_error("Error reading: ", filename);
        return false;
    }
    String base_dir(filename);
    base_dir.baseDir();
    //String base_dir = filename;
    //size_t fnsize;
    //if ((fnsize = base_dir.find_last_of("/")) > 0)
    //      base_dir = base_dir.subString(1,fnsize);
    while (!conffiles.eof()) {
        getline(conffiles, linebuffer);
        if (!conffiles.fail() && linebuffer.length() != 0) {
            if (linebuffer[0] != '#') { // i.e. not commented out
                temp = (char *) linebuffer.c_str();
                if (temp.contains("#")) {
                    temp = temp.before("#");
                }
                temp.removeWhiteSpace(); // get rid of spaces at end of line
                // check for LISTDIR and add replace with now_pwd
                while (temp.contains("__LISTDIR__")) {
                    String temp2 = temp.before("__LISTDIR__");
                    temp2 += now_pwd;
                    temp2 += temp.after("__LISTDIR__");
                    temp = temp2;
                }

                // deal with included files
                if (temp.startsWith(".")) {
                    String temp2 = temp.after(".Include<").before(">");
                    if (temp2.length() > 0) {
                        temp2.fullPath(base_dir);
                        if (!readConfFile(temp2.toCharArray(), now_pwd)) {
                            conffiles.close();
                            return false;
                        }
                        continue;
                    }
                    temp2 = temp.after(".Define LISTDIR <").before(">");
                    if (temp2.length() > 0) {
                        now_pwd = temp2;
                        if(!now_pwd.endsWith("/"))
                            now_pwd += "/";
                    }

                    continue;
                }
                // append ,listdir=now_pwd if line contains a file path - so that now_pwd can be passed
                // to list file handler so that it can honour __LISTDIR__ in Included listfiles
                if (temp.contains("path=") && !temp.contains("listdir=")) {
                    temp += ",listdir=";
                    temp += now_pwd;
                }
                linebuffer = temp.toCharArray();
                conffile.push_back(linebuffer); // stick option in deque
            }
        }
    }
    conffiles.close();
    return true;
}

bool FOptionContainer::read(const char *filename) {
    try { // all sorts of exceptions could occur reading conf files
        std::string linebuffer;
        String temp; // for tempory conversion and storage
        String list_pwd;
        if(!readConfFile(filename, list_pwd)){
            logger_error("Error reading: "s + filename);
            return false;
        }
        logger_trace("Read conf into memory: ", filename);

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

        if (findoptionS("contentscanexceptions") == "on") {
            content_scan_exceptions = true;
        } else {
            content_scan_exceptions = false;
        }

        logger_debug("disable_content_scan: ", String(disable_content_scan),
                    " disablecontentscanerror: ", String(disable_content_scan_error),
                    " contentscanexceptions: ", String(content_scan_exceptions) );

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
#ifdef E2DEBUG
            int size = (int) text_mime.size();
            int i;
            for (i = 0; i < size; i++) {
                logger_debug("mimes filtering : ", text_mime[i]);
            }
#endif
        }


        if (findoptionS("sslcheckcert") == "on") {
            if(o.enable_ssl) {
                ssl_check_cert = true;
                } else {
                    logger_error("Warning: To use sslcheckcert, enablessl in e2guardian.conf must be on");
                    ssl_check_cert = false;
                }
        } else {
            ssl_check_cert = false;
        }

        if (findoptionS("sslmitm") == "on") {
            if(o.enable_ssl) {
                ssl_mitm = true;

                if (findoptionS("automitm") == "off") {
                    automitm= false;
                } else {
                    automitm= true;
                }

                if (findoptionS("mitmcheckcert") == "off")
                    mitm_check_cert = false;

                allow_empty_host_certs = false;
                if (findoptionS("allowemptyhostcert") == "on")
                    allow_empty_host_certs = true;
            } else {
                syslog(LOG_ERR, "Warning: To use sslmitm, enablessl in e2guardian.conf must be on");
                std::cerr << thread_id << "Warning: sslmitm requires ssl to be enabled in e2guardian.conf " << std::endl;
                ssl_mitm = false;
            }
        } else {
            ssl_mitm = false;
        }

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
                    std::cerr << thread_id << "notifyav cannot be on while usesmtp is off." << std::endl;
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
                    std::cerr << thread_id << "notifycontent cannot be on while usesmtp is off." << std::endl;
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
                    std::cerr << thread_id << "avadmin cannot be blank while notifyav is on." << std::endl;
                syslog(LOG_ERR, "avadmin cannot be blank while notifyav is on.");
                return false;
            }
        }

        contentadmin = findoptionS("contentadmin");
        if (contentadmin.length() == 0) {
            if (use_smtp) {
                if (!is_daemonised)
                    std::cerr << thread_id << "contentadmin cannot be blank while usesmtp is on." << std::endl;
                syslog(LOG_ERR, "contentadmin cannot be blank while usesmtp is on.");
                return false;
            }
        }

        mailfrom = findoptionS("mailfrom");
        if (mailfrom.length() == 0) {
            if (use_smtp) {
                if (!is_daemonised)
                    std::cerr << thread_id << "mailfrom cannot be blank while usesmtp is on." << std::endl;
                syslog(LOG_ERR, "mailfrom cannot be blank while usesmtp is on.");
                return false;
            }
        }
        avsubject = findoptionS("avsubject");
        if (avsubject.length() == 0 && notifyav == 1 && use_smtp == 1) {
            if (!is_daemonised)
                std::cerr << thread_id << "avsubject cannot be blank while notifyav is on." << std::endl;
            syslog(LOG_ERR, "avsubject cannot be blank while notifyav is on.");
            return false;
        }

        contentsubject = findoptionS("contentsubject");
        if (contentsubject.length() == 0 && use_smtp) {
            if (!is_daemonised)
                std::cerr << thread_id << "contentsubject cannot be blank while usesmtp is on." << std::endl;
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
            logger_error("Reporting_level is : ", String(reporting_level), " file ", filename);
        }

        long temp_max_upload_size;
        temp_max_upload_size = findoptionI("maxuploadsize");
        if ((realitycheck(temp_max_upload_size, -1, 10000000, "max_uploadsize")) && (temp_max_upload_size != 0)) {
            max_upload_size = temp_max_upload_size;
            if (temp_max_upload_size > 0)
                max_upload_size *= 1024;
        } else {
            logger_error( "Invalid maxuploadsize: ", String(temp_max_upload_size) );
            return false;
        }
        logger_debug("maxuploadsize: ", String(temp_max_upload_size) );

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
                    logger_error("Warning accessdeniedaddress setting appears to be wrong.");
                }
            }
        }
        if (reporting_level == 3) {
            if (access_denied_domain.length() > 1) {
                logger_error("Warning accessdeniedaddress setting appears to be wrong in reportinglevel 3");
                return false;
            }
            // override default banned page
            String html_template(findoptionS("htmltemplate"));
            if (html_template != "") {
                html_template = o.languagepath + html_template;
                banned_page = new HTMLTemplate;
                if (!(banned_page->readTemplateFile(html_template.toCharArray()))) {
                    logger_error("Error reading HTML Template file: ", html_template);
                    return false;
                }
            } else {
                html_template = o.languagepath + "template.html";
                banned_page = new HTMLTemplate;
                if (!(banned_page->readTemplateFile(html_template.toCharArray()))) {
                    logger_error("Error reading default HTML Template file: ", html_template);
                    return false;
                }
            }

            String neterr_template(findoptionS("neterrtemplate"));
            if (neterr_template != "") {
                neterr_template = o.languagepath + neterr_template;
                neterr_page = new HTMLTemplate;
                if (!(neterr_page->readTemplateFile(neterr_template.toCharArray()))) {
                    if (!is_daemonised) {
                        std::cerr << thread_id << "Error reading NetErr HTML Template file: " << neterr_template
                                  << std::endl;
                    }
                    syslog(LOG_ERR, "Error reading NetErr HTML Template file: %s", neterr_template.toCharArray());
                    return false;
                    // HTML template file
                }
            } else {  // if blank will default to HTML template file
                neterr_template = o.languagepath + "neterr_template.html";
                neterr_page = new HTMLTemplate;
                if (!(neterr_page->readTemplateFile(neterr_template.toCharArray()))) {
                    if (!is_daemonised) {
                        std::cerr << thread_id << "Error reading default HTML and NetErr Template file: " << html_template << std::endl;
                    }
                    syslog(LOG_ERR, "Error reading default HTML and NetErr Template file: %s", html_template.toCharArray());
                    return false;
	        }
	    } 
        }

        if (findoptionS("nonstandarddelimiter") == "off") {
            non_standard_delimiter = false;
        } else {
            non_standard_delimiter = true;
        }

        // grab group name (if not using external group names file)
        if (!o.use_group_names_list) {
	        if (findoptionS("groupname").length() > 0) {
            	name = findoptionS("groupname");
	        } else {
		        name = "no_name_group";
	        }
            logger_debug("Group name: ", name);
        }

        embedded_url_weight = findoptionI("embeddedurlweight");
        logger_debug("Embedded URL Weight: ", std::to_string(embedded_url_weight));

        category_threshold = findoptionI("categorydisplaythreshold");
        logger_debug("Category display threshold: ", std::to_string(category_threshold));

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

        logger_trace("Read settings into memory");

        logger_trace("Reading phrase, URL and site lists into memory");
        if (weighted_phrase_mode > 0) {
            naughtyness_limit = findoptionI("naughtynesslimit");
            if (!realitycheck(naughtyness_limit, 1, 0, "naughtynesslimit"))
                return false;

            if (!o.lm.readbplfile(banned_phrase_list_location.c_str(),
                                  exception_phrase_list_location.c_str(),
                                  weighted_phrase_list_location.c_str(), banned_phrase_list,
                                  force_quick_search, naughtyness_limit)) {
                return false;
            } // read banned, exception, weighted phrase list
            banned_phrase_flag = true;
        }

        {
            std::deque<String> dq = findoptionM("ipsitelist");
            logger_debug("ipsitelist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_IPSITE, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("iplist");
            logger_debug("iplist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_IP, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("timelist");
            logger_debug("timelist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_TIME, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("sitelist");
            logger_debug("sitelist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_SITE, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("urllist");
            logger_debug("urllist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_URL, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("searchlist");
            logger_debug("searchlist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_SEARCH, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("fileextlist");
            logger_debug("fileextlist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_FILE_EXT, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("mimelist");
            logger_debug("mimelist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_MIME, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("regexpboollist");
            logger_debug("regexpboollist deque is size ", String(dq.size()) );
            if(!LMeta.load_type(LIST_TYPE_REGEXP_BOOL, dq)) return false;
        }

        {
            std::deque<String> dq = findoptionM("regexpreplacelist");
            logger_debug("regexpreplacelist deque is size ", String(dq.size()) );
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
                                              force_quick_search, naughtyness_limit)) {
                            return false;
                        }
                        searchterm_flag = true;
                    }
                }
            }
	    
	std::string content_regexp_list_location(findoptionS("contentregexplist"));
	if (content_regexp_list_location.length() > 1) {
		unsigned int content_regexp_list;
		if (!LMeta.readRegExReplacementFile(content_regexp_list_location.c_str(), list_pwd.toCharArray(), "contentregexplist", content_regexp_list, content_regexp_list_rep, content_regexp_list_comp)) {
             		return false;
		} else {
			content_regexp_flag = true;
		} 
	} else {
			content_regexp_flag = false;
	}

    logger_trace("Lists in memory");

    logger_trace("Read Storyboard");
    if (!StoryB.readFile(storyboard_location.c_str(), LMeta, true))
        return false;


    if(!StoryB.setEntry(ENT_STORYB_PROXY_REQUEST,"checkrequest")) {
        std::cerr << thread_id << "Required storyboard entry function 'checkrequest' is missing" << std::endl;
        return false;
    }

    if(!StoryB.setEntry(ENT_STORYB_PROXY_RESPONSE,"checkresponse")) {
	 std::cerr << thread_id << "Required storyboard entry function 'checkresponse' is missing" << std::endl;
         return false;
    }

    if(!StoryB.setEntry(ENT_STORYB_LOG_CHECK,"checklogging")) {
            std::cerr << thread_id << "Required storyboard entry function 'checklogging' is missing" << std::endl;
            return false;
    }

    if((o.transparenthttps_port > 0) && !StoryB.setEntry(ENT_STORYB_THTTPS_REQUEST,"thttps-checkrequest")) {
         std::cerr << thread_id << "Required storyboard entry function 'thttps-checkrequest' is missing" << std::endl;
         return false;
    }

    if((o.icap_port > 0) && !StoryB.setEntry(ENT_STORYB_ICAP_REQMOD,"icap-checkrequest")) {
          std::cerr << thread_id << "Required storyboard entry function 'icap-checkrequest' is missing" << std::endl;
          return false;
    }

    if((o.icap_port > 0) && !StoryB.setEntry(ENT_STORYB_ICAP_RESMOD,"icap-checkresponse")) {
           std::cerr << thread_id << "Required storyboard entry function 'icap-checkresponse' is missing" << std::endl;
           return false;
    }

    if (o.dm_entry_dq.size() > 0)  {
            for (std::deque<struct OptionContainer::SB_entry_map>::const_iterator i = o.dm_entry_dq.begin(); i != o.dm_entry_dq.end(); ++i) {
                if (!StoryB.setEntry(i->entry_id, i->entry_function)) {
                    std::cerr << thread_id << "Required DM storyboard entry function" << i->entry_function.c_str()
                              << " is missing from pre_auth.stoary" << std::endl;
                }
            }
        }
    
    if (!precompileregexps()) {
        return false;
    } // precompiled reg exps for speed

    //
    //
    // Bypass/infection bypass modes
    //
    //

    cgi_bypass = (findoptionS("cgibypass")== "on" );
    cgi_infection_bypass = (findoptionS("cgiinfectionbypass") == "on");

    bypass_version = findoptionI("bypassversion");
    if (!realitycheck(bypass_version, 0, 2, "bypassversion")) {
        return false;
    }
    if (bypass_version == 0) bypass_version = 2;   //default
    if (bypass_version == 2) bypass_v2 = true;   //default

    bypass_mode = findoptionI("bypass");
    if (!realitycheck(bypass_mode, -1, 0, "bypass")) {
        return false;
    }


    if(bypass_mode == -1) cgi_bypass = true;   // for backward compatibility

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
#ifdef E2DEBUG
        std::cerr << thread_id << "Setting magic key to '" << magic << "'" << std::endl;
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

    if(infection_bypass_mode == -1) cgi_infection_bypass = true;   // for backward compatibility


    if (infection_bypass_mode != 0) {
        imagic = findoptionS("infectionbypasskey");
        if (imagic.length() < 9) {
            std::string s(16u, ' ');
            for (int i = 0; i < 16; i++) {
                s[i] = (rand() % 26) + 'A';
            }
            imagic = s;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "Setting imagic key to '" << imagic << "'" << std::endl;
#endif
        if (findoptionS("infectionbypasserrorsonly") == "off") {
            infection_bypass_errors_only = false;
        } else {
#ifdef E2DEBUG
            std::cerr << thread_id << "Only allowing infection bypass on scan error" << std::endl;
#endif
            infection_bypass_errors_only = true;
        }
    }

        if (findoptionS("scanbypass") == "on") {
            scan_bypass = true;
        } else {
            scan_bypass = false;
        }


    if(((cgi_bypass)||(cgi_infection_bypass)) && (bypass_version == 2)) {
        cgi_magic = findoptionS("cgikey");
        if ( cgi_magic.length() < 9 ) {
            std::cerr << thread_id << "A valid cgikey must be provided with bypass cgi version 2" << std::endl;
            return false;
        };
        cgi_bypass_v2 = true;
        if(cgi_infection_bypass && infection_bypass_mode < 60) {
            std::cerr << thread_id << "infectionbypassmode must be greater than 60 with bypass cgi version 2" << std::endl;
            return false;
        } else if(bypass_mode < 60) {
            std::cerr << thread_id << "bypassmode must be greater than 60 with bypass cgi version 2" << std::endl;
            return false;
        }

    }
            } catch (std::exception &e) {
        if (!is_daemonised) {
            std::cerr << thread_id << e.what() << std::endl; // when called the daemon has not
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
//    for (int i = 0; i < (signed)conffile.size(); i++)
    for (int i = (signed)conffile.size() - 1; i > -1; i--)   // reverse search so that later entries will overwrite any earlier ones.
    {
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
//            if (temp.startsWith("'")) { // inverted commas
//                temp.lop();
//            }
            temp.removeMultiChar('\'');
            while (temp.endsWith(" ")) { // get rid of tailing spaces
                temp.chop();
            }
  //          if (temp.endsWith("'")) { // inverted commas
  //              temp.chop();
   //         }
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

            std::cerr << thread_id << "Config problem; check allowed values for " << emessage << std::endl;
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
            std::cerr << thread_id << "Error compiling RegExp isiphost." << std::endl;
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
