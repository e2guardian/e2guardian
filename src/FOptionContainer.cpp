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
#include <netdb.h>		// for gethostby
#include <netinet/in.h>		// for address structures
#include <arpa/inet.h>		// for inet_aton()
#include <sys/socket.h>
//#include <unistd.h>  // remove


// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;


// IMPLEMENTATION

// reverse DNS lookup on IP. be aware that this can return multiple results, unlike a standard lookup.
std::deque<String> * ipToHostname(const char *ip)
{
	std::deque<String> *result = new std::deque<String>;
	struct in_addr address, **addrptr;
	if (inet_aton(ip, &address)) {	// convert to in_addr
		struct hostent *answer;
		answer = gethostbyaddr((char *) &address, sizeof(address), AF_INET);
		if (answer) {	// sucess in reverse dns
			result->push_back(String(answer->h_name));
			for (addrptr = (struct in_addr **) answer->h_addr_list; *addrptr; addrptr++) {
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
	if (banned_phrase_flag) o.lm.deRefList(banned_phrase_list);
	if (searchterm_flag) o.lm.deRefList(searchterm_list);
	if (exception_site_flag) o.lm.deRefList(exception_site_list);
	if (exception_url_flag) o.lm.deRefList(exception_url_list);
	if (banned_extension_flag) o.lm.deRefList(banned_extension_list);
	if (banned_mimetype_flag) o.lm.deRefList(banned_mimetype_list);
	if (banned_site_flag) o.lm.deRefList(banned_site_list);
	if (banned_url_flag) o.lm.deRefList(banned_url_list);
	if (grey_site_flag) o.lm.deRefList(grey_site_list);
	if (grey_url_flag) o.lm.deRefList(grey_url_list);
	if (banned_regexpurl_flag) o.lm.deRefList(banned_regexpurl_list);
	if (exception_regexpurl_flag) o.lm.deRefList(exception_regexpurl_list);
	if (banned_regexpheader_flag) o.lm.deRefList(banned_regexpheader_list);
	if (content_regexp_flag) o.lm.deRefList(content_regexp_list);
	if (url_regexp_flag) o.lm.deRefList(url_regexp_list);
	if (header_regexp_flag) o.lm.deRefList(header_regexp_list);
	if (exception_extension_flag) o.lm.deRefList(exception_extension_list);
	if (exception_mimetype_flag) o.lm.deRefList(exception_mimetype_list);
	if (exception_file_site_flag) o.lm.deRefList(exception_file_site_list);
	if (exception_file_url_flag) o.lm.deRefList(exception_file_url_list);
	if (log_site_flag) o.lm.deRefList(log_site_list);
	if (log_url_flag) o.lm.deRefList(log_url_list);
	if (log_regexpurl_flag) o.lm.deRefList(log_regexpurl_list);
	//if (searchengine_regexp_flag) o.lm.deRefList(searchengine_regexp_list);
#ifdef PRT_DNSAUTH
	if (auth_exception_site_flag) o.lm.deRefList(auth_exception_site_list);
	if (auth_exception_url_flag) o.lm.deRefList(auth_exception_url_list);
#endif
#ifdef REFEREREXCEPT
	if (referer_exception_site_flag) o.lm.deRefList(referer_exception_site_list);
	if (referer_exception_url_flag) o.lm.deRefList(referer_exception_url_list);
#endif
#ifdef ADDHEADER
	if (addheader_regexp_flag) o.lm.deRefList(addheader_regexp_list);
#endif
#ifdef SEARCHWORDS
	if (banned_search_flag) o.lm.deRefList(banned_search_list);
	if (search_regexp_flag) o.lm.deRefList(search_regexp_list);
#ifdef LOCAL_LISTS
	if (local_banned_search_flag) o.lm.deRefList(local_banned_search_list);
	if (banned_search_overide_flag) o.lm.deRefList(banned_search_overide_list);
#endif
#endif
#ifdef LOCAL_LISTS
	if (local_exception_site_flag) o.lm.deRefList(local_exception_site_list);
	if (local_exception_url_flag) o.lm.deRefList(local_exception_url_list);
	if (local_banned_site_flag) o.lm.deRefList(local_banned_site_list);
	if (local_banned_url_flag) o.lm.deRefList(local_banned_url_list);
	if (local_grey_site_flag) o.lm.deRefList(local_grey_site_list);
	if (local_grey_url_flag) o.lm.deRefList(local_grey_url_list);
#ifdef SSL_EXTRA_LISTS
	if (local_banned_ssl_site_flag) o.lm.deRefList(local_banned_ssl_site_list);
	if (local_grey_ssl_site_flag) o.lm.deRefList(local_grey_ssl_site_list);
#endif
#endif

#ifdef SSL_EXTRA_LISTS
	if (banned_ssl_site_flag) o.lm.deRefList(banned_ssl_site_list);
	if (grey_ssl_site_flag) o.lm.deRefList(grey_ssl_site_list);
#endif

	banned_phrase_flag = false;
	searchterm_flag = false;
	exception_site_flag = false;
	exception_url_flag = false;
	banned_extension_flag = false;
	banned_mimetype_flag = false;
	banned_site_flag = false;
	banned_url_flag = false;
	grey_site_flag = false;
	grey_url_flag = false;
	banned_regexpurl_flag = false;
	exception_regexpurl_flag = false;
	banned_regexpheader_flag = false;
	content_regexp_flag = false;
	url_regexp_flag = false;
	header_regexp_flag = false;
	exception_extension_flag = false;
	exception_mimetype_flag = false;
	exception_file_site_flag = false;
	exception_file_url_flag = false;
	log_site_flag = false;
	log_url_flag = false;
	log_regexpurl_flag = false;
	//searchengine_regexp_flag = false;
#ifdef PRT_DNSAUTH
	auth_exception_site_flag = false;
	auth_exception_url_flag = false;
#endif
#ifdef REFEREREXCEPT
	referer_exception_site_flag = false;
	referer_exception_url_flag = false;
#endif
#ifdef LOCAL_LISTS
	use_only_local_allow_lists = false;
	local_exception_site_flag = false;
	local_exception_url_flag = false;
	local_banned_site_flag = false;
	local_banned_url_flag = false;
	local_grey_site_flag = false;
	local_grey_url_flag = false;
#ifdef SSL_EXTRA_LISTS
	local_banned_ssl_site_flag = false;
	local_grey_ssl_site_flag = false;
#endif
#endif
#ifdef ADDHEADER
	addheader_regexp_flag = false;
	addheader_regexp_list_comp.clear();
	addheader_regexp_list_rep.clear();
#endif
#ifdef SEARCHWORDS
	banned_search_flag = false;
	search_regexp_flag = false;
	search_regexp_list_comp.clear();
	search_regexp_list_rep.clear();
#ifdef LOCAL_LISTS
	local_banned_search_flag = false;
	banned_search_overide_flag = false;
#endif
#endif
#ifdef SSL_EXTRA_LISTS
	banned_ssl_site_flag = false;
	grey_ssl_site_flag = false;
#endif
	
	block_downloads = false;
	
	banned_phrase_list_index.clear();
	
//	conffile.clear();
	
	content_regexp_list_comp.clear();
	content_regexp_list_rep.clear();
	url_regexp_list_comp.clear();
	url_regexp_list_rep.clear();
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
HTMLTemplate* FOptionContainer::getHTMLTemplate()
{
	if (banned_page)
		return banned_page;
	return &(o.html_template);
}

// read in the given file, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw, and create a cache file if desired.
// listname is used in error messages.
bool FOptionContainer::readFile(const char *filename, unsigned int* whichlist, bool sortsw, bool cache, const char *listname)
{
	int res = o.lm.newItemList(filename, sortsw, 1, true);
	if (res < 0) {
		if (!is_daemonised) {
			std::cerr << "Error opening " << listname << std::endl;
		}
		syslog(LOG_ERR, "Error opening %s", listname);
		return false;
	}
	(*whichlist) = (unsigned) res;
	if (!(*o.lm.l[(*whichlist)]).used) {
		if (sortsw)
			(*o.lm.l[(*whichlist)]).doSort(true);
		else
			(*o.lm.l[(*whichlist)]).doSort(false);
		if (cache && createlistcachefiles) {
			if (!(*o.lm.l[(*whichlist)]).createCacheFile()) {
				return false;
			}
		}
		(*o.lm.l[(*whichlist)]).used = true;
	}
	return true;
}

bool FOptionContainer::read(const char *filename)
{
	try {			// all sorts of exceptions could occur reading conf files
		std::string linebuffer;
		String temp;  // for tempory conversion and storage
		std::ifstream conffiles(filename, std::ios::in);  // e2guardianfN.conf
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
				if (linebuffer[0] != '#') {	// i.e. not commented out
					temp = (char *) linebuffer.c_str();
					if (temp.contains("#")) {
						temp = temp.before("#");
					}
					temp.removeWhiteSpace();  // get rid of spaces at end of line
					linebuffer = temp.toCharArray();
					conffile.push_back(linebuffer);  // stick option in deque
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

#ifdef LOCAL_LISTS
		if (findoptionS("useonlylocalallowlists") == "on") {
			use_only_local_allow_lists = true;
		} else {
			use_only_local_allow_lists = false;
		}
#endif

#ifdef __SSLCERT
		if (findoptionS("sslcheckcert") == "on") {
			ssl_check_cert = true;
		} else {
			ssl_check_cert = false;
		}
#endif //__SSLCERT

#ifdef __SSLMITM
		if (findoptionS("sslmitm") == "on") {
			ssl_mitm = true;
			mitm_magic = findoptionS("mitmkey");
			if (mitm_magic.length() < 9) {
				std::string s(16u, ' ');
				for (int i = 0; i < 16; i++) {
					s[i] = (rand() % 26) + 'A';
				}
				mitm_magic = s;
			}
#ifdef DGDEBUG
			std::cout << "Setting mitm_magic key to '" << mitm_magic << "'" << std::endl;
#endif
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
		current_violations=0;
		violationbody="";

		threshold = findoptionI("threshold");

		avadmin = findoptionS("avadmin");
		if (avadmin.length()==0) {
			if (notifyav==1) {
				if (!is_daemonised)
					std::cerr << "avadmin cannot be blank while notifyav is on." << std::endl;
				syslog(LOG_ERR, "avadmin cannot be blank while notifyav is on.");
				return false;
			}
		}

		contentadmin = findoptionS("contentadmin");
		if (contentadmin.length()==0) {
			if (use_smtp) {		   
				if (!is_daemonised)		   
					std::cerr << "contentadmin cannot be blank while usesmtp is on." << std::endl;
				syslog(LOG_ERR, "contentadmin cannot be blank while usesmtp is on.");
				return false;
			}
		}

		mailfrom = findoptionS("mailfrom");
		if (mailfrom.length()==0) {
			if (use_smtp) {
				if (!is_daemonised)		   
					std::cerr << "mailfrom cannot be blank while usesmtp is on." << std::endl;
				syslog(LOG_ERR, "mailfrom cannot be blank while usesmtp is on.");
				return false;
			}
		}	   
		avsubject = findoptionS("avsubject");
		if (avsubject.length()==0 && notifyav==1 && use_smtp==1) {
			if (!is_daemonised)		   
				std::cerr << "avsubject cannot be blank while notifyav is on." << std::endl;
			syslog(LOG_ERR, "avsubject cannot be blank while notifyav is on.");
			return false;
		}

		contentsubject = findoptionS("contentsubject");
		if (contentsubject.length()==0 && use_smtp) {
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

                if (realitycheck(temp_max_upload_size, -1, 10000000, "max_uploadsize")) {
                       max_upload_size = temp_max_upload_size;
                       if (temp_max_upload_size > 0)
                               max_upload_size *= 1024;
               }
               else{
                       if (!is_daemonised)
                               std::cerr << "Invalid maxuploadsize: " << temp_max_upload_size << std::endl;
                               syslog(LOG_ERR, "Invalid maxuploadsize: %ld", temp_max_upload_size);
                               return false;
                }               

#ifdef DGDEBUG
                std::cout << "Group " <<  findoptionS("groupname") << "(" << filtergroup << ") Max upload size in e2guardian group file: " << temp_max_upload_size << std::endl;
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
					access_denied_domain = access_denied_domain.before(":");  // chop off the port number if any
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
			}

		// override ssl default banned page
               	sslaccess_denied_address = findoptionS("sslaccessdeniedaddress");
		if ((sslaccess_denied_address.length() != 0 ) && (reporting_level == 3)) {
                	        sslaccess_denied_domain = sslaccess_denied_address.c_str();
                       		sslaccess_denied_domain = sslaccess_denied_domain.after("://");
                       		sslaccess_denied_domain.removeWhiteSpace();
                        if (sslaccess_denied_domain.contains("/")) {
                                sslaccess_denied_domain = sslaccess_denied_domain.before("/");  // access_denied_domain now contains the FQ host nom of the
                                // server that serves the accessdenied.html file
                        }
                        if (sslaccess_denied_domain.contains(":")) {
                                sslaccess_denied_domain = sslaccess_denied_domain.before(":");  // chop off the port number if any
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
		}

                if (findoptionS("nonstandarddelimiter") == "off") {
                        non_standard_delimiter = false;
                } else {
                        non_standard_delimiter = true;
                }

		// group mode: 0 = banned, 1 = filtered, 2 = exception
		group_mode = findoptionI("groupmode");
		if ((group_mode < 0) || (group_mode > 2)) {
			if (!is_daemonised)
				std::cerr<<"Invalid groupmode"<<std::endl;
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
			// deque.  They are only seperate files for clarity.

			if (findoptionS("enablepics") == "on") {
				enable_PICS = true;
			} else {
				enable_PICS = false;
			}

                        if (findoptionS("bannedregexwithblanketblock") == "on") {
                                 enable_regex_grey = true;
                         } else {
                                 enable_regex_grey = false;
                         }

			if (findoptionS("blockdownloads") == "on") {
				block_downloads = true;
			}

			if (enable_PICS) {
				linebuffer = findoptionS("picsfile");
				std::ifstream picsfiles(linebuffer.c_str(), std::ios::in);  // pics file
				if (!picsfiles.good()) {
					if (!is_daemonised) {
						std::cerr << "Error reading PICS file: " << linebuffer << std::endl;
					}
					syslog(LOG_ERR, "Error reading PICS file: %s", linebuffer.c_str());
					return false;
				}
				while (!picsfiles.eof()) {
					getline(picsfiles, linebuffer);
					if (!picsfiles.eof() && linebuffer.length() != 0) {
						if (linebuffer[0] != '#') {	// i.e. not commented out
							temp = (char *) linebuffer.c_str();
							if (temp.contains("#")) {
								temp = temp.before("#");
							}
							while (temp.endsWith(" ")) {
								temp.chop();  // get rid of spaces at end of line
							}
							linebuffer = temp.toCharArray();
							conffile.push_back(linebuffer);  // stick option in deque
						}
					}
				}
				picsfiles.close();

#ifdef DGDEBUG
				std::cout << "Read PICS into memory" << std::endl;
			} else {
				std::cout << "PICS disabled" << std::endl;
#endif
			}

			// Support weighted phrase mode per group
			if (findoptionS("weightedphrasemode").length() > 0)
			{
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
			std::string banned_url_list_location(findoptionS("bannedurllist"));
			std::string grey_site_list_location(findoptionS("greysitelist"));
			std::string grey_url_list_location(findoptionS("greyurllist"));
			std::string banned_regexpurl_list_location(findoptionS("bannedregexpurllist"));
			std::string exception_regexpurl_list_location(findoptionS("exceptionregexpurllist"));
			std::string banned_regexpheader_list_location(findoptionS("bannedregexpheaderlist"));
			std::string content_regexp_list_location(findoptionS("contentregexplist"));
			std::string url_regexp_list_location(findoptionS("urlregexplist"));
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
			//std::string searchengine_regexp_list_location(findoptionS("searchengineregexplist"));

#ifdef PRT_DNSAUTH
			std::string auth_exceptions_site_list_location(findoptionS("authexceptionsitelist"));
			std::string auth_exceptions_url_list_location(findoptionS("authexceptionurllist"));
#endif
#ifdef RXREDIRECTS
			std::string url_redirect_regexp_list_location(findoptionS("urlredirectregexplist"));
#endif
#ifdef REFEREREXCEPT
			std::string referer_exceptions_site_list_location(findoptionS("refererexceptionsitelist"));
			std::string referer_exceptions_url_list_location(findoptionS("refererexceptionurllist"));
#endif
#ifdef ADDHEADER
			std::string addheader_regexp_list_location(findoptionS("addheaderregexplist"));
#endif
#ifdef SEARCHWORDS
			std::string banned_search_list_location(findoptionS("bannedsearchlist"));
			std::string search_regexp_list_location(findoptionS("searchregexplist"));
#ifdef LOCAL_LISTS
			std::string local_banned_search_list_location(findoptionS("localbannedsearchlist"));
			std::string banned_search_overide_list_location(findoptionS("bannedsearchoveridelist"));
#endif
#endif
#ifdef LOCAL_LISTS
			std::string local_banned_site_list_location(findoptionS("localbannedsitelist"));
			std::string local_banned_url_list_location(findoptionS("localbannedurllist"));
			std::string local_grey_site_list_location(findoptionS("localgreysitelist"));
			std::string local_grey_url_list_location(findoptionS("localgreyurllist"));
			std::string local_exceptions_site_list_location(findoptionS("localexceptionsitelist"));
			std::string local_exceptions_url_list_location(findoptionS("localexceptionurllist"));
#ifdef SSL_EXTRA_LISTS
			std::string local_banned_ssl_site_list_location(findoptionS("localbannedsslsitelist"));
			std::string local_grey_ssl_site_list_location(findoptionS("localgreysslsitelist"));
#endif 
# endif

#ifdef SSL_EXTRA_LISTS
			std::string banned_ssl_site_list_location(findoptionS("bannedsslsitelist"));
			std::string grey_ssl_site_list_location(findoptionS("greysslsitelist"));
#endif 

			if (enable_PICS) {
				pics_rsac_nudity = findoptionI("RSACnudity");
				pics_rsac_language = findoptionI("RSAClanguage");
				pics_rsac_sex = findoptionI("RSACsex");
				pics_rsac_violence = findoptionI("RSACviolence");
				pics_evaluweb_rating = findoptionI("evaluWEBrating");
				pics_cybernot_sex = findoptionI("CyberNOTsex");
				pics_cybernot_other = findoptionI("CyberNOTother");
				pics_safesurf_agerange = findoptionI("SafeSurfagerange");
				pics_safesurf_profanity = findoptionI("SafeSurfprofanity");
				pics_safesurf_heterosexualthemes = findoptionI("SafeSurfheterosexualthemes");
				pics_safesurf_homosexualthemes = findoptionI("SafeSurfhomosexualthemes");
				pics_safesurf_nudity = findoptionI("SafeSurfnudity");
				pics_safesurf_violence = findoptionI("SafeSurfviolence");
				pics_safesurf_sexviolenceandprofanity = findoptionI("SafeSurfsexviolenceandprofanity");
				pics_safesurf_intolerance = findoptionI("SafeSurfintolerance");
				pics_safesurf_druguse = findoptionI("SafeSurfdruguse");
				pics_safesurf_otheradultthemes = findoptionI("SafeSurfotheradultthemes");
				pics_safesurf_gambling = findoptionI("SafeSurfgambling");
				pics_icra_chat = findoptionI("ICRAchat");
				pics_icra_moderatedchat = findoptionI("ICRAmoderatedchat");
				pics_icra_languagesexual = findoptionI("ICRAlanguagesexual");
				pics_icra_languageprofanity = findoptionI("ICRAlanguageprofanity");
				pics_icra_languagemildexpletives = findoptionI("ICRAlanguagemildexpletives");
				pics_icra_nuditygraphic = findoptionI("ICRAnuditygraphic");
				pics_icra_nuditymalegraphic = findoptionI("ICRAnuditymalegraphic");
				pics_icra_nudityfemalegraphic = findoptionI("ICRAnudityfemalegraphic");
				pics_icra_nuditytopless = findoptionI("ICRAnuditytopless");
				pics_icra_nuditybottoms = findoptionI("ICRAnuditybottoms");
				pics_icra_nuditysexualacts = findoptionI("ICRAnuditysexualacts");
				pics_icra_nudityobscuredsexualacts = findoptionI("ICRAnudityobscuredsexualacts");
				pics_icra_nuditysexualtouching = findoptionI("ICRAnuditysexualtouching");
				pics_icra_nuditykissing = findoptionI("ICRAnuditykissing");
				pics_icra_nudityartistic = findoptionI("ICRAnudityartistic");
				pics_icra_nudityeducational = findoptionI("ICRAnudityeducational");
				pics_icra_nuditymedical = findoptionI("ICRAnuditymedical");
				pics_icra_drugstobacco = findoptionI("ICRAdrugstobacco");
				pics_icra_drugsalcohol = findoptionI("ICRAdrugsalcohol");
				pics_icra_drugsuse = findoptionI("ICRAdrugsuse");
				pics_icra_gambling = findoptionI("ICRAgambling");
				pics_icra_weaponuse = findoptionI("ICRAweaponuse");
				pics_icra_intolerance = findoptionI("ICRAintolerance");
				pics_icra_badexample = findoptionI("ICRAbadexample");
				pics_icra_pgmaterial = findoptionI("ICRApgmaterial");
				pics_icra_violenceobjects = findoptionI("ICRAviolenceobjects");
				pics_icra_violencerape = findoptionI("ICRAviolencerape");
				pics_icra_violencetohumans = findoptionI("ICRAviolencetohumans");
				pics_icra_violencetoanimals = findoptionI("ICRAviolencetoanimals");
				pics_icra_violencetofantasy = findoptionI("ICRAviolencetofantasy");
				pics_icra_violencekillinghumans = findoptionI("ICRAviolencekillinghumans");
				pics_icra_violencekillinganimals = findoptionI("ICRAviolencekillinganimals");
				pics_icra_violencekillingfantasy = findoptionI("ICRAviolencekillingfantasy");
				pics_icra_violenceinjuryhumans = findoptionI("ICRAviolenceinjuryhumans");
				pics_icra_violenceinjuryanimals = findoptionI("ICRAviolenceinjuryanimals");
				pics_icra_violenceinjuryfantasy = findoptionI("ICRAviolenceinjuryfantasy");
				pics_icra_violenceartisitic = findoptionI("ICRAviolenceartisitic");
				pics_icra_violenceeducational = findoptionI("ICRAviolenceeducational");
				pics_icra_violencemedical = findoptionI("ICRAviolencemedical");
				pics_icra_violencesports = findoptionI("ICRAviolencesports");
				pics_weburbia_rating = findoptionI("Weburbiarating");
				pics_vancouver_multiculturalism = findoptionI("Vancouvermulticulturalism");
				pics_vancouver_educationalcontent = findoptionI("Vancouvereducationalcontent");
				pics_vancouver_environmentalawareness = findoptionI("Vancouverenvironmentalawareness");
				pics_vancouver_tolerance = findoptionI("Vancouvertolerance");
				pics_vancouver_violence = findoptionI("Vancouverviolence");
				pics_vancouver_sex = findoptionI("Vancouversex");
				pics_vancouver_profanity = findoptionI("Vancouverprofanity");
				pics_vancouver_safety = findoptionI("Vancouversafety");
				pics_vancouver_canadiancontent = findoptionI("Vancouvercanadiancontent");
				pics_vancouver_commercialcontent = findoptionI("Vancouvercommercialcontent");
				pics_vancouver_gambling = findoptionI("Vancouvergambling");
				
				// new Korean PICS support
				pics_icec_rating = findoptionI("ICECrating");
				pics_safenet_nudity = findoptionI("SafeNetnudity");
				pics_safenet_language = findoptionI("SafeNetlanguage");
				pics_safenet_sex = findoptionI("SafeNetsex");
				pics_safenet_violence = findoptionI("SafeNetviolence");
				pics_safenet_gambling = findoptionI("SafeNetgambling");
				pics_safenet_alcoholtobacco = findoptionI("SafeNetalcoholtobacco");
			}
#ifdef DGDEBUG
			else
				std::cout << "PICS disabled; options skipped" << std::endl;
#endif

#ifdef DGDEBUG
			std::cout << "Read settings into memory" << std::endl;
			std::cout << "Reading phrase, URL and site lists into memory" << std::endl;
#endif

			if (!block_downloads) {
#ifdef DGDEBUG
				std::cout << "Blanket download block disabled; using standard banned file lists" << std::endl;
#endif
				if (!readFile(banned_extension_list_location.c_str(),&banned_extension_list,false,false,"bannedextensionlist")) {
					return false;
				}		// file extensions
				banned_extension_flag = true;
				if (!readFile(banned_mimetype_list_location.c_str(),&banned_mimetype_list,false,true,"bannedmimetypelist")) {
					return false;
				}		// mime types
				banned_mimetype_flag = true;
			}
			if (!readFile(exception_extension_list_location.c_str(),&exception_extension_list,false,false,"exceptionextensionlist")) {
				return false;
			}		// file extensions
			exception_extension_flag = true;
			if (!readFile(exception_mimetype_list_location.c_str(),&exception_mimetype_list,false,true,"exceptionmimetypelist")) {
				return false;
			}		// mime types
			exception_mimetype_flag = true;
			if (!readFile(exception_file_site_list_location.c_str(),&exception_file_site_list,false,true,"exceptionfilesitelist")) {
				return false;
			}		// download site exceptions
			exception_file_site_flag = true;
			if (!readFile(exception_file_url_list_location.c_str(),&exception_file_url_list,true,true,"exceptionfileurllist")) {
				return false;
			}		// download site exceptions
			exception_file_url_flag = true;

			if (weighted_phrase_mode > 0)
			{
				naughtyness_limit = findoptionI("naughtynesslimit");
				if (!realitycheck(naughtyness_limit, 1, 0, "naughtynesslimit"))
					return false;
				
				if (!o.lm.readbplfile(banned_phrase_list_location.c_str(),
					exception_phrase_list_location.c_str(),
					weighted_phrase_list_location.c_str(), banned_phrase_list,
					force_quick_search))
				{
					return false;
				}		// read banned, exception, weighted phrase list
				banned_phrase_flag = true;
			}
			
			if (!readFile(exceptions_site_list_location.c_str(),&exception_site_list,false,true,"exceptionsitelist")) {
				return false;
			}		// site exceptions
			exception_site_flag = true;
			if (!readFile(exceptions_url_list_location.c_str(),&exception_url_list,true,true,"exceptionurllist")) {
				return false;
			}		// url exceptions
			exception_url_flag = true;
			if (!readFile(banned_site_list_location.c_str(),&banned_site_list,false,true,"bannedsitelist")) {
				return false;
			}		// banned domains
			banned_site_flag = true;
			if (!readFile(banned_url_list_location.c_str(),&banned_url_list,true,true,"bannedurllist")) {
				return false;
			}		// banned urls
			banned_url_flag = true;
			if (!readFile(grey_site_list_location.c_str(),&grey_site_list,false,true,"greysitelist")) {
				return false;
			}		// grey domains
			grey_site_flag = true;
			if (!readFile(grey_url_list_location.c_str(),&grey_url_list,true,true,"greyurllist")) {
				return false;
			}		// grey urls
			grey_url_flag = true;

#ifdef PRT_DNSAUTH
			if (!readFile(auth_exceptions_site_list_location.c_str(),&auth_exception_site_list,false,true,"authexceptionsitelist")) {
				return false;
			}		// non_auth site exceptions
			auth_exception_site_flag = true;
			if (!readFile(auth_exceptions_url_list_location.c_str(),&auth_exception_url_list,true,true,"authexceptionurllist")) {
				return false;
			}		// non-auth url exceptions
			auth_exception_url_flag = true;
#endif
#ifdef REFEREREXCEPT
			if (!readFile(referer_exceptions_site_list_location.c_str(),&referer_exception_site_list,false,true,"refererexceptionsitelist")) {
				return false;
			}		// referer site exceptions
			referer_exception_site_flag = true;
			if (!readFile(referer_exceptions_url_list_location.c_str(),&referer_exception_url_list,true,true,"refererexceptionurllist")) {
				return false;
			}		// referer url exceptions
			referer_exception_url_flag = true;
#endif
#ifdef ADDHEADER
			if (!readRegExReplacementFile(addheader_regexp_list_location.c_str(),"addheaderregexplist",addheader_regexp_list,addheader_regexp_list_rep,addheader_regexp_list_comp)) {
				return false;
			}  // url regular expressions for header insertions
			addheader_regexp_flag = true;
#endif

#ifdef SEARCHWORDS
			if (banned_search_list_location.length() && readFile(banned_search_list_location.c_str(),&banned_search_list,true,true,"bannedsearchlist")) {
				banned_search_flag = true;
			}
			else {
				banned_search_flag = false;
			}		// banned search words

			if (search_regexp_list_location.length() && readRegExReplacementFile(search_regexp_list_location.c_str(),"searchregexplist",search_regexp_list,search_regexp_list_rep,search_regexp_list_comp)) {
				search_regexp_flag = true;
#ifdef DGDEBUG
				std::cout << "Enabled search term extraction RegExp list" << std::endl;
#endif
			} 
			else {
				search_regexp_flag = false;
			}  // search engine searchwords regular expressions

#ifdef LOCAL_LISTS
			if (local_banned_search_list_location.length() && readFile(local_banned_search_list_location.c_str(),&local_banned_search_list,true,true,"localbannedsearchlist")) {
				local_banned_search_flag = true;
			}
			else {
				local_banned_search_flag = false;
			}		// local banned search words

			if (banned_search_overide_list_location.length() && readFile(banned_search_overide_list_location.c_str(),&banned_search_overide_list,true,true,"bannedsearchoveridelist")) {
				banned_search_overide_flag = true;
			}
			else {
				banned_search_overide_flag = false;
			}		// banned search overide words
#endif
#endif
#ifdef LOCAL_LISTS
			if (!readFile(local_exceptions_site_list_location.c_str(),&local_exception_site_list,false,true,"localexceptionsitelist")) {
				return false;
			}		// site exceptions
			local_exception_site_flag = true;
			if (!readFile(local_exceptions_url_list_location.c_str(),&local_exception_url_list,true,true,"localexceptionurllist")) {
				return false;
			}		// url exceptions
			local_exception_url_flag = true;
			if (!readFile(local_banned_site_list_location.c_str(),&local_banned_site_list,false,true,"localbannedsitelist")) {
				return false;
			}		// banned domains
			local_banned_site_flag = true;
			if (!readFile(local_banned_url_list_location.c_str(),&local_banned_url_list,true,true,"localbannedurllist")) {
				return false;
			}		// banned urls
			local_banned_url_flag = true;
			if (!readFile(local_grey_site_list_location.c_str(),&local_grey_site_list,false,true,"localgreysitelist")) {
				return false;
			}		// grey domains
			local_grey_site_flag = true;
			if (!readFile(local_grey_url_list_location.c_str(),&local_grey_url_list,true,true,"localgreyurllist")) {
				return false;
			}		// grey urls
			local_grey_url_flag = true;
#ifdef SSL_EXTRA_LISTS
			if (!readFile(local_banned_ssl_site_list_location.c_str(),&local_banned_ssl_site_list,false,true,"localbannedsslsitelist")) {
				return false;
			}		// banned domains
			local_banned_ssl_site_flag = true;
			if (!readFile(local_grey_ssl_site_list_location.c_str(),&local_grey_ssl_site_list,false,true,"localgreysslsitelist")) {
				return false;
			}		// grey domains
			local_grey_ssl_site_flag = true;
#endif
#endif
#ifdef SSL_EXTRA_LISTS
			if (!readFile(banned_ssl_site_list_location.c_str(),&banned_ssl_site_list,false,true,"bannedsslsitelist")) {
				return false;
			}		// banned domains
			banned_ssl_site_flag = true;
			if (!readFile(grey_ssl_site_list_location.c_str(),&grey_ssl_site_list,false,true,"greysslsitelist")) {
				return false;
			}		// grey domains
			grey_ssl_site_flag = true;
#endif
			
			
			// log-only lists
			if (log_url_list_location.length() && readFile(log_url_list_location.c_str(), &log_url_list, true, true, "logurllist")) {
				log_url_flag = true;
#ifdef DGDEBUG
				std::cout << "Enabled log-only URL list" << std::endl;
#endif
			}
			if (log_site_list_location.length() && readFile(log_site_list_location.c_str(), &log_site_list, false, true, "logsitelist")) {
				log_site_flag = true;
#ifdef DGDEBUG
				std::cout << "Enabled log-only domain list" << std::endl;
#endif
			}
			if (log_regexpurl_list_location.length() && readRegExMatchFile(log_regexpurl_list_location.c_str(), "logregexpurllist", log_regexpurl_list,
				log_regexpurl_list_comp, log_regexpurl_list_source, log_regexpurl_list_ref))
			{
				log_regexpurl_flag = true;
#ifdef DGDEBUG
				std::cout << "Enabled log-only RegExp URL list" << std::endl;
#endif
			}

			// search term blocking
//			if (searchengine_regexp_list_location.length() && readRegExMatchFile(searchengine_regexp_list_location.c_str(), "searchengineregexplist", searchengine_regexp_list,
//				searchengine_regexp_list_comp, searchengine_regexp_list_source, searchengine_regexp_list_ref))
			if (search_regexp_flag)
			{
				if (weighted_phrase_mode > 0)
				{
					searchterm_limit = findoptionI("searchtermlimit");
					if (!realitycheck(searchterm_limit, 0, 0, "searchtermlimit")) {
						return false;
					}

					// Optionally override the normal phrase lists for search term blocking.
					// We need all three lists to build a phrase tree, so fail if we encounter
					// anything other than all three enabled/disabled simultaneously.
					if (searchterm_limit > 0)
					{
						std::string exception_searchterm_list_location(findoptionS("exceptionsearchtermlist"));
						std::string weighted_searchterm_list_location(findoptionS("weightedsearchtermlist"));
						std::string banned_searchterm_list_location(findoptionS("bannedsearchtermlist"));
						if (!(exception_searchterm_list_location.length() == 0 &&
							weighted_searchterm_list_location.length() == 0 &&
							banned_searchterm_list_location.length() == 0))
						{
							// At least one is enabled - try to load all three.
							if (!o.lm.readbplfile(banned_searchterm_list_location.c_str(),
								exception_searchterm_list_location.c_str(),
								weighted_searchterm_list_location.c_str(), searchterm_list,
								force_quick_search))
							{
								return false;
							}
							searchterm_flag = true;
						}
					}
				}
			}

			if (!readRegExMatchFile(banned_regexpurl_list_location.c_str(),"bannedregexpurllist",banned_regexpurl_list,
				banned_regexpurl_list_comp, banned_regexpurl_list_source, banned_regexpurl_list_ref))
			{
				return false;
			}		// banned reg exp urls
			banned_regexpurl_flag = true;

			if (!readRegExMatchFile(exception_regexpurl_list_location.c_str(),"exceptionregexpurllist",exception_regexpurl_list,
				exception_regexpurl_list_comp, exception_regexpurl_list_source, exception_regexpurl_list_ref))
			{
				return false;
			}		// exception reg exp urls
			exception_regexpurl_flag = true;

			if (!readRegExMatchFile(banned_regexpheader_list_location.c_str(), "bannedregexpheaderlist", banned_regexpheader_list,
				banned_regexpheader_list_comp, banned_regexpheader_list_source, banned_regexpheader_list_ref))
			{
				return false;
			}		// banned reg exp headers
			banned_regexpheader_flag = true;


			if (!readRegExReplacementFile(content_regexp_list_location.c_str(),"contentregexplist",content_regexp_list,content_regexp_list_rep,content_regexp_list_comp)) {
				return false;
			}		// content replacement regular expressions
			content_regexp_flag = true;

			if (!readRegExReplacementFile(url_regexp_list_location.c_str(),"urlregexplist",url_regexp_list,url_regexp_list_rep,url_regexp_list_comp)) {
				return false;
			}  // url replacement regular expressions
			url_regexp_flag = true;

			if (!readRegExReplacementFile(header_regexp_list_location.c_str(), "headerregexplist", header_regexp_list, header_regexp_list_rep, header_regexp_list_comp)) {
				return false;
			}  // header replacement regular expressions
			header_regexp_flag = true;
#ifdef DGDEBUG
			std::cout << "Lists in memory" << std::endl;
#endif
		}

		if (!precompileregexps()) {
			return false;
		}		// precompiled reg exps for speed

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
	}
	catch(std::exception & e) {
		if (!is_daemonised) {
			std::cerr << e.what() << std::endl;  // when called the daemon has not
			// detached so we can do this
		}
		return false;
	}
	return true;
}

// read regexp url list
bool FOptionContainer::readRegExMatchFile(const char *filename, const char *listname, unsigned int& listref,
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
	listref = (unsigned) result;
	return compileRegExMatchFile(listref, list_comp, list_source, list_ref);
}

// NOTE TO SELF - MOVE TO LISTCONTAINER TO SOLVE FUDGE
// compile regexp url list
bool FOptionContainer::compileRegExMatchFile(unsigned int list, std::deque<RegExp> &list_comp,
	std::deque<String> &list_source, std::deque<unsigned int> &list_ref)
{
	for (unsigned int i = 0; i < (*o.lm.l[list]).morelists.size(); i++) {
		if (!compileRegExMatchFile((*o.lm.l[list]).morelists[i],list_comp,list_source,list_ref)) {
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
bool FOptionContainer::readRegExReplacementFile(const char *filename, const char *listname, unsigned int& listid,
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
	listid = (unsigned) result;
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
		if (regexp.length() < 1) {	// allow replace with nothing
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
char *FOptionContainer::testBlanketBlock(unsigned int list, bool ip, bool ssl) {
	if (not o.lm.l[list]->isNow())
		return NULL;
	if (o.lm.l[list]->blanketblock) {
		o.lm.l[list]->lastcategory = "-";
		return (char*)o.language_list.getTranslation(502);
	} else if (o.lm.l[list]->blanket_ip_block and ip) {
		o.lm.l[list]->lastcategory = "IP";
		return (char*)o.language_list.getTranslation(505);
	} else if (o.lm.l[list]->blanketsslblock and ssl) {
		o.lm.l[list]->lastcategory = "HTTPS";
		return (char*)o.language_list.getTranslation(506);
	} else if (o.lm.l[list]->blanketssl_ip_block and ssl and ip) {
		o.lm.l[list]->lastcategory = "HTTPS_IP";
		return (char*)o.language_list.getTranslation(507);
	}
	for (std::vector<int>::iterator i = o.lm.l[list]->morelists.begin(); i != o.lm.l[list]->morelists.end(); i++) {
		char *r = testBlanketBlock(*i, ip, ssl);
		if (r) {
			return r;
		}
	}
	return NULL;
}

// checkme: there's an awful lot of removing whitespace, PTP, etc. going on here.
// perhaps connectionhandler could keep a suitably modified version handy to prevent repitition of work?

char *FOptionContainer::inSiteList(String &url, unsigned int list, bool doblanket, bool ip, bool ssl)
{
	// Perform blanket matching if desired
	if (doblanket) {
		char *r = testBlanketBlock(list, ip, ssl);
		if (r) {
			return r;
		}
	}

	url.removeWhiteSpace();  // just in case of weird browser crap
	url.toLower();
	url.removePTP();  // chop off the ht(f)tp(s)://
	if (url.contains("/")) {
		url = url.before("/");  // chop off any path after the domain
	}
	char *i;
	bool isipurl = isIPHostname(url);
	if (reverse_lookups && isipurl) {	// change that ip into hostname
		std::deque<String > *url2s = ipToHostname(url.toCharArray());
		String url2;
		for (std::deque<String>::iterator j = url2s->begin(); j != url2s->end(); j++) {
			url2 = *j;
			while (url2.contains(".")) {
				i = (*o.lm.l[list]).findInList(url2.toCharArray());
				if (i != NULL) {
					delete url2s;
					return i;  // exact match
				}
				url2 = url2.after(".");  // check for being in hld
			}
		}
		delete url2s;
	}
	while (url.contains(".")) {
		i = (*o.lm.l[list]).findInList(url.toCharArray());
		if (i != NULL) {
			return i;  // exact match
		}
		url = url.after(".");  // check for being in higher level domains
	}
	if (url.length() > 1) {	// allows matching of .tld
		url = "." + url;
		i = (*o.lm.l[list]).findInList(url.toCharArray());
		if (i != NULL) {
			return i;  // exact match
		}
	}
	return NULL;  // and our survey said "UUHH UURRGHH"
}

#ifdef SEARCHWORDS
char *FOptionContainer::inSearchList(String &words, unsigned int list)
{
	char  *i = (*o.lm.l[list]).findInList(words.toCharArray());
	if (i != NULL) {
		return i;  // exact match
	}
	return NULL;  
}
#endif

// checkme: remove things like this & make inSiteList/inIPList public?

char *FOptionContainer::inBannedSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, banned_site_list, doblanket, ip, ssl);
}

bool FOptionContainer::inGreySiteList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef LOCAL_LISTS
	if (use_only_local_allow_lists) {
		return false;
	};
#endif
#ifdef SSL_EXTRA_LISTS
	if (ssl) {
	   return inSiteList(url, grey_ssl_site_list, doblanket, ip, ssl) != NULL;
	};
#endif
	return inSiteList(url, grey_site_list, doblanket, ip, ssl) != NULL;
}

#ifdef SSL_EXTRA_LISTS
char *FOptionContainer::inBannedSSLSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, banned_ssl_site_list, doblanket, ip, ssl);
}

bool FOptionContainer::inGreySSLSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, grey_ssl_site_list, doblanket, ip, ssl) != NULL;
}
#endif

#ifdef PRT_DNSAUTH
bool FOptionContainer::inAuthExceptionSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, auth_exception_site_list, doblanket, ip, ssl) != NULL;
}
#endif
#ifdef REFEREREXCEPT
bool FOptionContainer::inRefererExceptionLists(String url)
{
	if ((url.length() > 0) 
		&& ((inSiteList(url, referer_exception_site_list, false, false, false) != NULL)
		|| (inURLList(url, referer_exception_url_list, false, false, false) != NULL)) )
		return true;
	return false;
}
#endif
#ifdef SEARCHWORDS
char *FOptionContainer::inBannedSearchList(String words)
{
#ifdef LOCAL_LISTS
#ifdef DGDEBUG
    std::cout << "Checking Banned Search Overide list for " << words << std::endl;
#endif
	if ( inBannedSearchOverideList(words) )
		return NULL;
#endif
#ifdef DGDEBUG
    std::cout << "Checking Banned Search list for " << words << std::endl;
#endif
	return inSearchList(words, banned_search_list);
}

#ifdef LOCAL_LISTS
char *FOptionContainer::inLocalBannedSearchList(String words)
{
#ifdef DGDEBUG
    std::cout << "Checking Local Banned Search list for " << words << std::endl;
#endif
	return inSearchList(words, local_banned_search_list);
}
bool FOptionContainer::inBannedSearchOverideList(String words)
{
#ifdef DGDEBUG
    std::cout << "Checking Banned Search Overide list for " << words << std::endl;
#endif
	return inSearchList(words, banned_search_overide_list) != NULL;
}
#endif
#endif
#ifdef LOCAL_LISTS

bool FOptionContainer::inLocalExceptionSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, local_exception_site_list, doblanket, ip, ssl) != NULL;
}

char *FOptionContainer::inLocalBannedSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, local_banned_site_list, doblanket, ip, ssl);
}

bool FOptionContainer::inLocalGreySiteList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef SSL_EXTRA_LISTS
	if (ssl) {
	   return inSiteList(url, local_grey_ssl_site_list, doblanket, ip, ssl) != NULL;
	};
#endif
	return inSiteList(url, local_grey_site_list, doblanket, ip, ssl) != NULL;
}

#ifdef SSL_EXTRA_LISTS
char *FOptionContainer::inLocalBannedSSLSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, local_banned_ssl_site_list, doblanket, ip, ssl);
}

bool FOptionContainer::inLocalGreySSLSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, local_grey_ssl_site_list, doblanket, ip, ssl) != NULL;
}
#endif
#endif

bool FOptionContainer::inExceptionSiteList(String url, bool doblanket, bool ip, bool ssl)
{
	return inSiteList(url, exception_site_list, doblanket, ip, ssl) != NULL;
}

bool FOptionContainer::inExceptionFileSiteList(String url)
{
	if (inSiteList(url, exception_file_site_list) != NULL)
		return true;
	else
		return inURLList(url, exception_file_url_list) != NULL;
}

// look in given URL list for given URL
char *FOptionContainer::inURLList(String &url, unsigned int list, bool doblanket, bool ip, bool ssl) {
	if (ssl) {  // can't be in url list as SSL is site only
		return NULL;
	};
	// Perform blanket matching if desired
	if (doblanket) {
		char *r = testBlanketBlock(list, ip, ssl);
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
	url.removeWhiteSpace();  // just in case of weird browser crap
	url.toLower();
	url.removePTP();  // chop off the ht(f)tp(s)://
	if (url.contains("/")) {
		String tpath("/");
		tpath += url.after("/");
		url = url.before("/");
		tpath.hexDecode();
		tpath.realPath();
		url += tpath;  // will resolve ../ and %2e2e/ and // etc
	}
	if (url.endsWith("/")) {
		url.chop();  // chop off trailing / if any
	}
#ifdef DGDEBUG
	std::cout << "inURLList (processed): " << url << std::endl;
#endif
	if (reverse_lookups && url.after("/").length() > 0) {
		String hostname(url.getHostname());
		if (isIPHostname(hostname)) {
			std::deque<String > *url2s = ipToHostname(hostname.toCharArray());
			String url2;
			for (std::deque<String>::iterator j = url2s->begin(); j != url2s->end(); j++) {
				url2 = *j;
				url2 += "/";
				url2 += url.after("/");
				while (url2.before("/").contains(".")) {
					i = (*o.lm.l[list]).findStartsWith(url2.toCharArray());
					if (i != NULL) {
						foundurl = i;
						fl = foundurl.length();
						if (url2.length() > fl) {
							unsigned char c = url[fl];
							if (c == '/' || c == '?' || c == '&' || c == '=') {
								delete url2s;
								return i;  // matches /blah/ or /blah/foo
								// (or /blah?foo etc.)
								// but not /blahfoo
							}
						} else {
							delete url2s;
							return i;  // exact match
						}
					}
					url2 = url2.after(".");  // check for being in hld
				}
			}
			delete url2s;
		}
	}
	while (url.before("/").contains(".")) {
		i = (*o.lm.l[list]).findStartsWith(url.toCharArray());
		if (i != NULL) {
			foundurl = i;
			fl = foundurl.length();
#ifdef DGDEBUG
			std::cout << "foundurl: " << foundurl << foundurl.length() << std::endl;
			std::cout << "url: " << url << fl << std::endl;
#endif
			if (url.length() > fl) {
				if (url[fl] == '/' || url[fl] == '?' || url[fl] == '&' || url[fl] == '=') {
					return i;  // matches /blah/ or /blah/foo but not /blahfoo
				}
			} else {
				return i;  // exact match
			}
		}
		url = url.after(".");  // check for being in higher level domains
	}
	return NULL;
}

char *FOptionContainer::inBannedURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inBannedURLList"<<std::endl;
#endif
	return inURLList(url, banned_url_list, doblanket, ip, ssl);
}

bool FOptionContainer::inGreyURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inGreyURLList"<<std::endl;
#endif
#ifdef LOCAL_LISTS
	if (use_only_local_allow_lists) {
		return false;
	};
#endif
	return inURLList(url, grey_url_list, doblanket, ip, ssl) != NULL;
}

bool FOptionContainer::inExceptionURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inExceptionURLList"<<std::endl;
#endif
	return inURLList(url, exception_url_list, doblanket, ip, ssl) != NULL;
}

#ifdef LOCAL_LISTS
char *FOptionContainer::inLocalBannedURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inLocalBannedURLList"<<std::endl;
#endif
	return inURLList(url, local_banned_url_list, doblanket, ip, ssl);
}

bool FOptionContainer::inLocalGreyURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inLocalGreyURLList"<<std::endl;
#endif
	return inURLList(url, local_grey_url_list, doblanket, ip, ssl) != NULL;
}

bool FOptionContainer::inLocalExceptionURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inLocalExceptionURLList"<<std::endl;
#endif
	return inURLList(url, local_exception_url_list, doblanket, ip, ssl) != NULL;
}

#endif

#ifdef PRT_DNSAUTH
bool FOptionContainer::inAuthExceptionURLList(String url, bool doblanket, bool ip, bool ssl)
{
#ifdef DGDEBUG
	std::cout<<"inAuthExceptionURLList"<<std::endl;
#endif
	return inURLList(url, auth_exception_url_list, doblanket, ip, ssl) != NULL;
}
#endif

// New log-only site lists
const char* FOptionContainer::inLogURLList(String url)
{
	if (!log_url_flag)
		return NULL;
	if (inURLList(url, log_url_list) != NULL) {
		return o.lm.l[log_url_list]->lastcategory.toCharArray();
	}
	return NULL;
}

const char* FOptionContainer::inLogSiteList(String url)
{
	if (!log_site_flag)
		return NULL;
	if (inSiteList(url, log_site_list) != NULL) {
		return o.lm.l[log_site_list]->lastcategory.toCharArray();
	}
	return NULL;
}

const char* FOptionContainer::inLogRegExpURLList(String url) {
	if (!log_regexpurl_flag)
		return NULL;
	int j = inRegExpURLList(url, log_regexpurl_list_comp, log_regexpurl_list_ref, log_regexpurl_list);
	if (j == -1)
		return NULL;
	return o.lm.l[log_regexpurl_list_ref[j]]->category.toCharArray();
}

// TODO: Store the modified URL somewhere, instead of re-processing it every time.

char *FOptionContainer::inExtensionList(unsigned int list, String url)
{
	url.removeWhiteSpace();  // just in case of weird browser crap
	url.toLower();
	url.hexDecode();
	url.removePTP();  // chop off the ht(f)tp(s)://
	url = url.after("/");  // chop off any domain before the path
	if (url.length() < 2) {	// will never match
		return NULL;
	}
	return (*o.lm.l[list]).findEndsWith(url.toCharArray());
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
int FOptionContainer::inBannedRegExpHeaderList(std::deque<String> &header)
{

	for (std::deque<String>::iterator k = header.begin(); k != header.end(); k++) {
#ifdef DGDEBUG
		std::cout << "inBannedRegExpHeaderList: " << *k << std::endl;
#endif
		unsigned int i = 0;
		for (std::deque<RegExp>::iterator j = banned_regexpheader_list_comp.begin(); j != banned_regexpheader_list_comp.end(); j++) {
			if (o.lm.l[banned_regexpheader_list_ref[i]]->isNow()) {
				j->match(k->toCharArray());
				if (j->matched())
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
int FOptionContainer::inRegExpURLList(String &url, std::deque<RegExp> &list_comp, std::deque<unsigned int> &list_ref, unsigned int list)
{
#ifdef DGDEBUG
	std::cout<<"inRegExpURLList: "<<url<<std::endl;
#endif
	// check parent list's time limit
	if (o.lm.l[list]->isNow()) {
		url.removeWhiteSpace();  // just in case of weird browser crap
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
			url += tpath;  // will resolve ../ and %2e2e/ and // etc
		}
		if (url.endsWith("/")) {
			url.chop();  // chop off trailing / if any
		}
		// re-add the PTP
		/*if (ptp.length() > 0)
			url = ptp + "//" + url;*/
#ifdef DGDEBUG
		std::cout<<"inRegExpURLList (processed): "<<url<<std::endl;
#endif
		unsigned int i = 0;
		for (std::deque<RegExp>::iterator j = list_comp.begin(); j != list_comp.end(); j++) {
			if (o.lm.l[list_ref[i]]->isNow()) {
				j->match(url.toCharArray());
				if (j->matched())
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
int FOptionContainer::inBannedRegExpURLList(String url)
{
#ifdef DGDEBUG
	std::cout<<"inBannedRegExpURLList"<<std::endl;
#endif
	return inRegExpURLList(url, banned_regexpurl_list_comp, banned_regexpurl_list_ref, banned_regexpurl_list);
}

int FOptionContainer::inExceptionRegExpURLList(String url)
{
#ifdef DGDEBUG
	std::cout<<"inExceptionRegExpURLList"<<std::endl;
#endif
	return inRegExpURLList(url, exception_regexpurl_list_comp, exception_regexpurl_list_ref, exception_regexpurl_list);
}

bool FOptionContainer::isIPHostname(String url)
{
	if (!isiphost.match(url.toCharArray())) {
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
	for (int i = 0; i < (signed) conffile.size(); i++) {
		temp = conffile[i].c_str();
		temp2 = temp.before("=");
		while (temp2.endsWith(" ")) {	// get rid of tailing spaces before =
			temp2.chop();
		}
		if (o == temp2) {
			temp = temp.after("=");
			while (temp.startsWith(" ")) {	// get rid of heading spaces
				temp.lop();
			}
			if (temp.startsWith("'")) {	// inverted commas
				temp.lop();
			}
			while (temp.endsWith(" ")) {	// get rid of tailing spaces
				temp.chop();
			}
			if (temp.endsWith("'")) {	// inverted commas
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
	if (!pics1.comp("pics-label\"[ \t]*content=[\'\"]([^>]*)[\'\"]")) {
		if (!is_daemonised) {
			std::cerr << "Error compiling RegExp pics1." << std::endl;
		}
		syslog(LOG_ERR, "%s", "Error compiling RegExp pics1.");
		return false;
	}
	if (!pics2.comp("[r|{ratings}] *\\(([^\\)]*)\\)")) {
		if (!is_daemonised) {
			std::cerr << "Error compiling RegExp pics2." << std::endl;
		}
		syslog(LOG_ERR, "%s", "Error compiling RegExp pics2.");
		return false;
	}
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
		url.removeWhiteSpace();  // just in case of weird browser crap
		url.toLower();
		url.removePTP();  // chop off the ht(f)tp(s)://
		if (url.contains("/")) {
			url = url.before("/");  // chop off any path after the domain
		}
		if (url.startsWith(access_denied_domain)) {	// don't filter our web server
			return true;
		}
	}
	return false;
}
