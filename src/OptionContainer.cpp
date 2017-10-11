// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "LOptionContainer.hpp"
#include "OptionContainer.hpp"
#include "RegExp.hpp"
#include "ConfigVar.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <syslog.h>
#include <dirent.h>
#include <cstdlib>
#include <unistd.h> // checkme: remove?

// GLOBALS

extern bool is_daemonised;



ListContainer total_block_site_list;
ListContainer total_block_url_list;

// IMPLEMENTATION

OptionContainer::OptionContainer()
    : use_filter_groups_list(false), stats_human_readable(false), auth_requires_user_and_group(false), use_group_names_list(false), auth_needs_proxy_query(false), prefer_cached_lists(false), no_daemon(false), no_logger(false), log_syslog(false), anonymise_logs(false), log_ad_blocks(false), log_timestamp(false), log_user_agent(false), soft_restart(false), delete_downloaded_temp_files(false), max_logitem_length(2000), max_content_filter_size(0), max_content_ramcache_scan_size(0), max_content_filecache_scan_size(0), scan_clean_cache(0), content_scan_exceptions(0), initial_trickle_delay(0), trickle_delay(0), content_scanner_timeout(0), reporting_level(0), weighted_phrase_mode(0), numfg(0), dstat_log_flag(false), dstat_interval(300), dns_user_logging(false), LC_cnt(0)
{
    log_Q = new Queue<std::string>;
    http_worker_Q = new Queue<Socket*>;
}


OptionContainer::~OptionContainer()
{
    reset();
}

void OptionContainer::reset()
{
    //deleteFilterGroups();
    deletePlugins(dmplugins);
    deletePlugins(csplugins);
    deletePlugins(authplugins);
    //deleteRooms();
    //exception_ip_list.reset();
    //banned_ip_list.reset();
    language_list.reset();
    conffile.clear();
    if (use_filter_groups_list)
        filter_groups_list.reset();
    filter_ip.clear();
    filter_ports.clear();
    auth_map.clear();
}


void OptionContainer::deletePlugins(std::deque<Plugin *> &list)
{
    for (std::deque<Plugin *>::iterator i = list.begin(); i != list.end(); i++) {
        if ((*i) != NULL) {
            (*i)->quit();
            delete (*i);
        }
    }
    list.clear();
}

bool OptionContainer::read(std::string& filename, int type)
{
	conffilename = filename;

	// all sorts of exceptions could occur reading conf files
	try {
		std::string linebuffer;
		String temp;  // for tempory conversion and storage
		std::ifstream conffiles(filename.c_str(), std::ios::in);  // e2guardian.conf
		if (!conffiles.good()) {
			if (!is_daemonised) {
				std::cerr << "error reading: " << filename.c_str() << std::endl;
			}
			syslog(LOG_ERR, "%s", "error reading e2guardian.conf");
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

                if (type == 0 || type == 2) {

                    if ((pid_filename = findoptionS("pidfilename")) == "") {
                        pid_filename = __PIDDIR;
                        pid_filename += "/e2guardian.pid";
                    }

                    if (findoptionS("logsyslog") == "on") {
                        log_syslog = true;
                        if ((name_suffix = findoptionS("namesuffix")) == "") {
                            name_suffix = "";
                        }
                    } else 	if ((log_location = findoptionS("loglocation")) == "") {
                        log_location = __LOGLOCATION;
                        log_location += "/access.log";
                        log_syslog = false;
                    }

                    if ((stat_location = findoptionS("statlocation")) == "") {
                        stat_location = __LOGLOCATION;
                        stat_location += "/stats";
                    }

                    if ((dstat_location = findoptionS("dstatlocation")) == "") {
                        dstat_log_flag = false;
                    } else {
                        dstat_log_flag = true;
                        dstat_interval = findoptionI("dstatinterval");
                        if ( dstat_interval  == 0) {
                            dstat_interval = 300; // 5 mins
                        }
                    }

                    if (findoptionS("statshumanreadable") == "on") {
                        stats_human_readable = true;
                    } else {
                        stats_human_readable = false;
                    }

                    if ((dns_user_logging_domain = findoptionS("dnsuserloggingdomain")) == "") {
                        dns_user_logging = false;
                    } else {
                        dns_user_logging = true;
                    }

                    log_header_value = findoptionS("logheadervalue");
                    if (type == 0) {
                        return true;
                    }
                }

		if ((daemon_user_name = findoptionS("daemonuser")) == "") {
			daemon_user_name = __PROXYUSER;
		}

		if ((daemon_group_name = findoptionS("daemongroup")) == "") {
			daemon_group_name = __PROXYGROUP;
		}

		blocked_content_store = findoptionS("blockedcontentstore");

		if (findoptionS("nodaemon") == "on") {
			no_daemon = true;
		} else {
			no_daemon = false;
		}

		if (findoptionS("nologger") == "on") {
			no_logger = true;
		} else {
			no_logger = false;
		}

		if (findoptionS("softrestart") == "on") {
			soft_restart = true;
		} else {
			soft_restart = false;
		}

#ifdef __SSLMITM
        ssl_certificate_path = findoptionS("sslcertificatepath") + "/";
        if (ssl_certificate_path == "/") {
            ssl_certificate_path = ""; // "" will enable default openssl certs
        }
#endif

#ifdef __SSLMITM
        if (findoptionS("enablessl") == "on") {
               enable_ssl  = true;
            } else {
                enable_ssl = false;
            }

       if(enable_ssl) {
        bool ret = true;
        ca_certificate_path = findoptionS("cacertificatepath");
        if (ca_certificate_path == "") {
		   if (!is_daemonised){
                    std::cerr << "cacertificatepath is required when ssl is enabled" << std::endl;
            }
            syslog(LOG_ERR, "%s", "cacertificatepath is required when ssl is enabled");
             ret = false;
        }

        ca_private_key_path = findoptionS("caprivatekeypath");
        if (ca_private_key_path == "") {
		   if (!is_daemonised){
                    std::cerr << "caprivatekeypath is required when ssl is enabled" << std::endl;
            }
            syslog(LOG_ERR, "%s", "caprivatekeypath is required when ssl is enabled");
             ret = false;
        }

        cert_private_key_path = findoptionS("certprivatekeypath");
        if (cert_private_key_path == "") {
		   if (!is_daemonised){
                    std::cerr << "certprivatekeypath is required when ssl is enabled" << std::endl;
            }
            syslog(LOG_ERR, "%s", "certprivatekeypath is required when ssl is enabled");
             ret = false;
        }

        generated_cert_path = findoptionS("generatedcertpath") + "/";
        if (generated_cert_path == "/") {
		   if (!is_daemonised){
                    std::cerr << "generatedcertpath is required when ssl is enabled" << std::endl;
            }
            syslog(LOG_ERR, "%s", "generatedcertpath is required when ssl is enabled");
             ret = false;
        }

        time_t gen_cert_start, gen_cert_end;
        time_t def_start = 1417872951; // 6th Dec 2014
        time_t ten_years = 315532800;
        gen_cert_start = findoptionI("generatedcertstart");
        if (gen_cert_start < def_start)
            gen_cert_start = def_start;
        gen_cert_end = findoptionI("generatedcertend");
        if (gen_cert_end < gen_cert_start)
            gen_cert_end = gen_cert_start + ten_years;

        set_cipher_list = findoptionS("setcipherlist");
        if (set_cipher_list == "")
            set_cipher_list = "HIGH:!ADH:!MD5:!RC4:!SRP:!PSK:!DSS";

//        if (ca_certificate_path != "" )
        if (ret) {
            	ca = new CertificateAuthority(ca_certificate_path.c_str(),
                ca_private_key_path.c_str(),
                cert_private_key_path.c_str(),
                generated_cert_path.c_str(),
                gen_cert_start, gen_cert_end);
        } else {
                return false;
            }
        }

#endif

#ifdef ENABLE_EMAIL
        // Email notification patch by J. Gauthier
        mailer = findoptionS("mailer");
#endif

        max_header_lines = findoptionI("maxheaderlines");
        if (max_header_lines == 0)
            max_header_lines= 40;
        if (!realitycheck(max_header_lines, 10, 250, "maxheaderlines")) {
            return false;
        }


        max_logitem_length = findoptionI("maxlogitemlength");
        // default of unlimited no longer allowed as could cause buffer overflow
        if (max_logitem_length == 0)
            max_logitem_length = 2000;
        if (!realitycheck(max_logitem_length, 10, 32000, "maxlogitemlength")) {
            return false;
        }

        proxy_timeout_sec = findoptionI("proxytimeout");
        if (!realitycheck(proxy_timeout_sec, 5, 100, "proxytimeout")) {
            return false;
        } // check its a reasonable value
        proxy_timeout = proxy_timeout_sec * 1000;

        proxy_failure_log_interval = findoptionI("proxyfailureloginterval");
        if (proxy_failure_log_interval == 0)
            proxy_failure_log_interval = 600; // 10 mins
        if (!realitycheck(proxy_failure_log_interval, proxy_timeout_sec, 3600, "proxyfailureloginterval")) {
            return false;
        } // check its a reasonable value

        pcon_timeout_sec = findoptionI("pcontimeout");
        if (!realitycheck(pcon_timeout_sec, 5, 300, "pcontimeout")) {
            return false;
        } // check its a reasonable value
        pcon_timeout = pcon_timeout_sec * 1000;

        exchange_timeout_sec = findoptionI("proxyexchange");
        if (!realitycheck(exchange_timeout_sec, 5, 300, "proxyexchange")) {
            return false;
        }
        exchange_timeout = exchange_timeout_sec  * 1000;

        http_workers= findoptionI("httpworkers");
        if (http_workers == 0) {
		http_workers = 100;
		if (!is_daemonised){
               		std::cerr << " http_workers settings cannot be zero: value set to 100" << std::endl;
		}
                syslog(LOG_ERR, "http_workers settings cannot be zero: value set to 100");
	}
        if (!realitycheck(http_workers, 20, 20000, "httpworkers")) {
        return false;
        } // check its a reasonable value

        monitor_helper = findoptionS("monitorhelper");
        if (monitor_helper == "") {
            monitor_helper_flag = false;
        } else {
            monitor_helper_flag = true;
        }

        monitor_flag_prefix = findoptionS("monitorflagprefix");
        if (monitor_flag_prefix == "") {
            monitor_flag_flag = false;
        } else {
            monitor_flag_flag = true;
        }

        max_content_filter_size = findoptionI("maxcontentfiltersize");
        if (!realitycheck(max_content_filter_size, 0, 0, "maxcontentfiltersize")) {
            return false;
        } // check its a reasonable value

        if (max_content_filter_size == 0) {
            max_content_filter_size = 1; // Minimal value 0 = 1
        }

        max_content_filter_size *= 1024;

        max_content_ramcache_scan_size = findoptionI("maxcontentramcachescansize");
        if (!realitycheck(max_content_ramcache_scan_size, 0, 0, "maxcontentramcachescansize")) {
            return false;
        }
        max_content_ramcache_scan_size *= 1024;

        max_content_filecache_scan_size = findoptionI("maxcontentfilecachescansize");
        if (!realitycheck(max_content_filecache_scan_size, 0, 0, "maxcontentfilecachescansize")) {
            return false;
        }
        max_content_filecache_scan_size *= 1024;

        if (max_content_ramcache_scan_size == 0) {
            max_content_ramcache_scan_size = max_content_filecache_scan_size;
        }

        weighted_phrase_mode = findoptionI("weightedphrasemode");
        if (!realitycheck(weighted_phrase_mode, 0, 2, "weightedphrasemode")) {
            return false;
        }
        /*
		if ((weighted_phrase_mode != 0)) {
			max_content_filter_size = max_content_ramcache_scan_size;
			if (max_content_filter_size == 0) {
				if (!is_daemonised)
					std::cerr << "maxcontent* settings cannot be zero (to disable phrase filtering, set weightedphrasemode to 0)" << std::endl;
				syslog(LOG_ERR, "%s", "maxcontent* settings cannot be zero (to disable phrase filtering, set weightedphrasemode to 0)");
				return false;
			}
		}
*/
        bool contentscanning = findoptionM("contentscanner").size() > 0;
        if (contentscanning) {

            if (max_content_filter_size > max_content_ramcache_scan_size) {
                if (!is_daemonised) {
                    std::cerr << "maxcontentfiltersize can not be greater than maxcontentramcachescansize" << std::endl;
                }
                syslog(LOG_ERR, "%s", "maxcontentfiltersize can not be greater than maxcontentramcachescansize");
                return false;
            }
            if (max_content_ramcache_scan_size > max_content_filecache_scan_size) {
                if (!is_daemonised) {
                    std::cerr << "maxcontentramcachescansize can not be greater than maxcontentfilecachescansize" << std::endl;
                }
                syslog(LOG_ERR, "%s", "maxcontentramcachescansize can not be greater than maxcontentfilecachescansize");
                return false;
            }

            trickle_delay = findoptionI("trickledelay");
            if (!realitycheck(trickle_delay, 1, 0, "trickledelay")) {
                return false;
            }
            initial_trickle_delay = findoptionI("initialtrickledelay");
            if (!realitycheck(initial_trickle_delay, 1, 0, "initialtrickledelay")) {
                return false;
            }

            content_scanner_timeout_sec = findoptionI("contentscannertimeout");
            if (!realitycheck(content_scanner_timeout_sec, 1, 0, "contentscannertimeout")) {
                return false;
            }
            content_scanner_timeout = content_scanner_timeout_sec * 1000;

            if (findoptionS("scancleancache") == "off") {
                scan_clean_cache = false;
            } else {
                scan_clean_cache = true;
            }

            if (findoptionS("contentscanexceptions") == "on") {
                content_scan_exceptions = true;
            } else {
                content_scan_exceptions = false;
            }
        }

        if (findoptionS("deletedownloadedtempfiles") == "off") {
            delete_downloaded_temp_files = false;
        } else {
            delete_downloaded_temp_files = true;
        }

        url_cache_number = findoptionI("urlcachenumber");
        if (!realitycheck(url_cache_number, 0, 0, "urlcachenumber")) {
            return false;
        } // check its a reasonable value

        url_cache_age = findoptionI("urlcacheage");
        if (!realitycheck(url_cache_age, 0, 0, "urlcacheage")) {
            return false;
        } // check its a reasonable value

        phrase_filter_mode = findoptionI("phrasefiltermode");
        if (!realitycheck(phrase_filter_mode, 0, 3, "phrasefiltermode")) {
            return false;
        }
        preserve_case = findoptionI("preservecase");
        if (!realitycheck(preserve_case, 0, 2, "preservecase")) {
            return false;
        }
        if (findoptionS("hexdecodecontent") == "on") {
            hex_decode_content = true;
        } else {
            hex_decode_content = false;
        }
        if (findoptionS("forcequicksearch") == "on") {
            force_quick_search = true;
        } else {
            force_quick_search = false;
        }

        if (findoptionS("mapportstoips") == "off") {
            map_ports_to_ips = false;
        } else {
            map_ports_to_ips = true;
        }

        if (findoptionS("mapauthtoports") == "off") {
            map_auth_to_ports = false;
        } else {
            map_auth_to_ports = true;
        }

        if (findoptionS("usecustombannedimage") == "off") {
            use_custom_banned_image = false;
        } else {
            use_custom_banned_image = true;
            custom_banned_image_file = findoptionS("custombannedimagefile");
            banned_image.read(custom_banned_image_file.c_str());
        }

        if (findoptionS("usecustombannedflash") == "off") {
            use_custom_banned_flash = false;
        } else {
            use_custom_banned_flash = true;
            custom_banned_flash_file = findoptionS("custombannedflashfile");
            banned_flash.read(custom_banned_flash_file.c_str());
        }

        proxy_port = findoptionI("proxyport");
        if (!realitycheck(proxy_port, 1, 65535, "proxyport")) {
            return false;
        } // etc
        proxy_ip = findoptionS("proxyip");

        // multiple listen IP support
        filter_ip = findoptionM("filterip");
        if (filter_ip.size() > 127) {
            if (!is_daemonised) {
                std::cerr << "Can not listen on more than 127 IPs" << std::endl;
            }
            syslog(LOG_ERR, "%s", "Can not listen on more than 127 IPs");
            return false;
        }
        filter_ports = findoptionM("filterports");
        if (map_ports_to_ips and filter_ports.size() != filter_ip.size()) {
            if (!is_daemonised) {
                std::cerr << "filterports (" << filter_ports.size() << ") must match number of filterips (" << filter_ip.size() << ")" << std::endl;
            }
            syslog(LOG_ERR, "%s", "filterports must match number of filterips");
            return false;
        }
        filter_port = filter_ports[0].toInteger();
        if (!realitycheck(filter_port, 1, 65535, "filterport[0]")) {
            return false;
        } // check its a reasonable value

#ifdef ENABLE_ORIG_IP
        if (findoptionS("originalip") == "on") {
            get_orig_ip = true;
        } else {
            get_orig_ip = false;
        }

#endif

        ll = findoptionI("loglevel");
        if (!realitycheck(ll, 0, 3, "loglevel")) {
            return false;
        } // etc
        log_file_format = findoptionI("logfileformat");
        if (!realitycheck(log_file_format, 1, 6, "logfileformat")) {
            return false;
        } // etc
        if (findoptionS("anonymizelogs") == "on") {
            anonymise_logs = true;
        } else {
            anonymise_logs = false;
        }
        if (findoptionS("logadblocks") == "on") {
            log_ad_blocks = true;
        } else {
            log_ad_blocks = false;
        }
        if (findoptionS("logtimestamp") == "on") {
            log_timestamp = true;
        } else {
            log_timestamp = false;
        }
        if (findoptionS("loguseragent") == "on") {
            log_user_agent = true;
        } else {
            log_user_agent = false;
        }

        logid_1.assign(findoptionS("logid1"));
        if (logid_1.empty())
            logid_1.assign("-");
        logid_2.assign(findoptionS("logid2"));
        if (logid_2.empty())
            logid_2.assign("-");

#ifdef SG_LOGFORMAT
        prod_id.assign(findoptionS("productid"));
        if (prod_id.empty())
            // SG '08
            prod_id.assign("2");
#endif

        if (findoptionS("showweightedfound") == "on") {
            show_weighted_found = true;
        } else {
            show_weighted_found = false;
        }
        reporting_level = findoptionI("reportinglevel");
        if (!realitycheck(reporting_level, -1, 3, "reportinglevel")) {
            return false;
        }
        languagepath = findoptionS("languagedir") + "/" + findoptionS("language") + "/";

        if (findoptionS("forwardedfor") == "on") {
            forwarded_for = true;
        } else {
            forwarded_for = false;
        }
        log_exception_hits = findoptionI("logexceptionhits");
        if (!realitycheck(log_exception_hits, 0, 3, "logexceptionhits")) {
            return false;
        }
        if (findoptionS("createlistcachefiles") == "off") {
            createlistcachefiles = false;
        } else {
            createlistcachefiles = true;
        }
        if (findoptionS("logconnectionhandlingerrors") == "on") {
            logconerror = true;
        } else {
            logconerror = false;
        }
        if (findoptionS("logchildprocesshandling") == "on") {
            logchildprocs = true;
        } else {
            logchildprocs = false;
        }

        if (findoptionS("logsslerrors") == "on") {
            log_ssl_errors = true;
        } else {
            log_ssl_errors = false;
        }

        if (findoptionS("reverseaddresslookups") == "on") {
            reverse_lookups = true;
        } else {
            reverse_lookups = false;
        }
        if (findoptionS("reverseclientiplookups") == "on") {
            reverse_client_ip_lookups = true;
        } else {
            reverse_client_ip_lookups = false;
        }
        if (findoptionS("logclienthostnames") == "on") {
            log_client_hostnames = true;
        } else {
            log_client_hostnames = false;
        }
	
	if (log_client_hostnames == true && reverse_client_ip_lookups == false){
            if (!is_daemonised) {
                std::cerr << "logclienthostnames enabled but reverseclientiplookups disabled" << std::endl;
            }
            syslog(LOG_ERR, "logclienthostnames enabled but reverseclientiplookups disabled");
            return false;
	}
        if (findoptionS("recheckreplacedurls") == "on") {
            recheck_replaced_urls = true;
        } else {
            recheck_replaced_urls = false;
        }

        if (findoptionS("usexforwardedfor") == "on") {
            use_xforwardedfor = true;
        } else {
            use_xforwardedfor = false;
        }

        xforwardedfor_filter_ip = findoptionM("xforwardedforfilterip");

        filter_groups = findoptionI("filtergroups");

        if (((per_room_directory_location = findoptionS("perroomdirectory")) != "") || ((per_room_directory_location = findoptionS("perroomblockingdirectory")) != "")) {
            //loadRooms(true);
        }

        if (!realitycheck(filter_groups, 1, 0, "filtergroups")) {
            return false;
        }
        if (filter_groups < 1) {
            if (!is_daemonised) {
                std::cerr << "filtergroups too small" << std::endl;
            }
            syslog(LOG_ERR, "filtergroups too small");
            return false;
        }

        if (!loadDMPlugins()) {
            if (!is_daemonised) {
                std::cerr << "Error loading DM plugins" << std::endl;
            }
            syslog(LOG_ERR, "Error loading DM plugins");
            return false;
        }

        // this needs to be known before loading CS plugins,
        // because ClamAV plugin makes use of it during init()
        download_dir = findoptionS("filecachedir");

        if (contentscanning) {
            if (!loadCSPlugins()) {
                if (!is_daemonised) {
                    std::cerr << "Error loading CS plugins" << std::endl;
                }
                syslog(LOG_ERR, "Error loading CS plugins");
                return false;
            }
        }

        if (!loadAuthPlugins()) {
            if (!is_daemonised) {
                std::cerr << "Error loading auth plugins" << std::endl;
            }
            syslog(LOG_ERR, "Error loading auth plugins");
            return false;
        }

        // check if same number of auth-plugin as ports if in
        //     authmaptoport mode
        if (map_auth_to_ports && (filter_ports.size() > 1)
            && (filter_ports.size() != authplugins.size())) {
            std::cerr << "In mapauthtoports mode you need to setup one port per auth plugin" << std::endl;
            return false;
        }

        // map port numbers to auth plugin names
        for (int i = 0; i < authplugins.size(); i++) {
            AuthPlugin *tmpPlugin = (AuthPlugin *)authplugins[i];
            String tmpStr = tmpPlugin->getPluginName();

            if ((!map_auth_to_ports) || filter_ports.size() == 1)
                auth_map[i] = tmpStr;
            else
                auth_map[filter_ports[i].toInteger()] = tmpStr;
        }

        // if the more than one port is being used, validate the combination of auth plugins
        if (authplugins.size() > 1 and filter_ports.size() > 1 and map_auth_to_ports) {
            std::deque<Plugin *>::iterator it = authplugins.begin();
            String firstPlugin;
            bool sslused = false;
            bool coreused = false;
            while (it != authplugins.end()) {
                AuthPlugin *tmp = (AuthPlugin *)*it;
                if (tmp->getPluginName().startsWith("proxy-basic")) {
                    if (!is_daemonised)
                        std::cerr << "Proxy auth is not possible with multiple ports" << std::endl;
                    syslog(LOG_ERR, "Proxy auth is not possible with multiple ports");
                    return false;
                }
                if (tmp->getPluginName().startsWith("proxy-ntlm") && (tmp->isTransparent() == false)) {
                    if (!is_daemonised)
                        std::cerr << "Non-transparent NTLM is not possible with multiple ports" << std::endl;
                    syslog(LOG_ERR, "Non-transparent NTLM is not possible with multiple ports");
                    return false;
                }
                if (it == authplugins.begin())
                    firstPlugin = tmp->getPluginName();
                else {
                    if ((firstPlugin == tmp->getPluginName()) and (!tmp->getPluginName().startsWith("ssl-core"))) {
                        if (!is_daemonised)
                            std::cerr << "Auth plugins can not be the same" << std::endl;
                        syslog(LOG_ERR, "Auth plugins can not be the same");
                        return false;
                    }
                }
                *it++;
            }
        }

        // if there's no auth enabled, we only need the first group's settings
        if (authplugins.size() == 0)
            filter_groups = 1;

        filter_groups_list_location = findoptionS("filtergroupslist");
        banned_ip_list_location = findoptionS("bannediplist");
        exception_ip_list_location = findoptionS("exceptioniplist");
        group_names_list_location = findoptionS("groupnamesfile");
        std::string language_list_location(languagepath + "messages");

        if (filter_groups_list_location.length() == 0) {
            use_filter_groups_list = false;
#ifdef DGDEBUG
            std::cout << "Not using filtergroupslist" << std::endl;
#endif
        } else {
            use_filter_groups_list = true;
            if ((findoptionS("authrequiresuserandgroup") == "on") && (authplugins.size() > 1))
                auth_requires_user_and_group = true;
        }

        if (group_names_list_location.length() == 0) {
            use_group_names_list = false;
#ifdef DGDEBUG
            std::cout << "Not using groupnameslist" << std::endl;
#endif
        } else {
            use_group_names_list = true;
        }

        if (findoptionS("prefercachedlists") == "on")
            prefer_cached_lists = true;
        else
            prefer_cached_lists = false;

        //if (!exception_ip_list.readIPMelangeList(exception_ip_list_location.c_str())) {
        //    std::cout << "Failed to read exceptioniplist" << std::endl;
        //    return false;
        //}
        //if (!banned_ip_list.readIPMelangeList(banned_ip_list_location.c_str())) {
        //    std::cout << "Failed to read bannediplist" << std::endl;
        //    return false;
        //}

        if (!language_list.readLanguageList(language_list_location.c_str())) {
            return false;
        } // messages language file


        if(!createLists(0))  {
                std::cerr << "Error reading filter group conf file(s)." << std::endl;
            syslog(LOG_ERR, "%s", "Error reading filter group conf file(s).");
            return false;
        }

//post read filtergroup config checks - only for SLLMITM for now

#ifdef _SSLMITM
        //bool ssl_mitm = false;
        //bool mitm_check_cert = false;
        //for (i = 0; i < numfg; i++) {
            //if (fg[i].ssl_mitm)
                //ssl_mitm = true;
            //if (fg[i].mitm_check_cert)
                //mitm_check_cert = true;
        //}

        if (enable_ssl) {
            if (ca_certificate_path != "") {
                ca = new CertificateAuthority(ca_certificate_path.c_str(),
                    ca_private_key_path.c_str(),
                    cert_private_key_path.c_str(),
                    generated_cert_path.c_str(),
                    gen_cert_start, gen_cert_end);
            } else {
                if (!is_daemonised) {
                    std::cerr << "Error - Valid cacertificatepath, caprivatekeypath and generatedcertpath must given when using MITM." << std::endl;
                }
                syslog(LOG_ERR, "%s", "Error - Valid cacertificatepath, caprivatekeypath and generatedcertpath must given when using MITM.");
                return false;
            }
        }
#endif

    } catch (std::exception &e) {
        if (!is_daemonised) {
            std::cerr << e.what() << std::endl; // when called the daemon has not
            // detached so we can do this
        }
        return false;
    }
    return true;
}

// read from stdin, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw
// listname is used in error messages.
bool OptionContainer::readStdin(ListContainer *lc, bool sortsw, const char *listname, const char *startstr)
{
    bool result = lc->readStdinItemList(sortsw, 1, startstr);
    if (!result) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    if (sortsw)
        lc->doSort(true);
    else
        lc->doSort(false);
    return true;
}

bool OptionContainer::readinStdin()
{
    String sitelist = "totalblocksitelist";
    String sitess = "#SITELIST";
    if (!readStdin(&total_block_site_list, false, sitelist.c_str(), sitess.c_str())) {
        return false;
    }
    total_block_site_flag = true;
    if (!readStdin(&total_block_url_list, true, "totalblockurllist", "#URLLIST")) {
        return false;
    }
    total_block_url_flag = true;
    return true;
}

char *OptionContainer::inSiteList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    String lastcategory;
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        url = url.before("/"); // chop off any path after the domain
    }
    char *i;
    //bool isipurl = isIPHostname(url);
    while (url.contains(".")) {
        i = lc->findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
        url = url.after("."); // check for being in higher level domains
    }
    if (url.length() > 1) { // allows matching of .tld
        url = "." + url;
        i = lc->findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
    }
    return NULL; // and our survey said "UUHH UURRGHH"
}

// look in given URL list for given URL
char *OptionContainer::inURLList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    unsigned int fl;
    char *i;
    String lastcategory;
    String foundurl;
#ifdef DGDEBUG
    std::cout << "inURLList: " << url << std::endl;
#endif
    //syslog(LOG_ERR, "inURLList url %s", url.c_str());
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
    //  syslog(LOG_ERR, "inURLList (processed) url %s", url.c_str());
    while (url.before("/").contains(".")) {
        i = lc->findStartsWith(url.toCharArray(), lastcategory);
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
#ifdef DGDEBUG
            std::cout << "foundurl: " << foundurl << foundurl.length() << std::endl;
            std::cout << "url: " << url << fl << std::endl;
#endif
            //syslog(LOG_ERR, "inURLList foundurl  %s", foundurl.c_str());
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

bool OptionContainer::inTotalBlockList(String &url)
{
    String murl = url;
    if (inSiteList(murl, &total_block_site_list, false, false)) {
        return true;
    }
    murl = url;
    if (inURLList(murl, &total_block_url_list, false, false)) {
        return true;
    }
    return false;
}

bool OptionContainer::doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort)
{
    bool result = lc->readItemList(filename, false, 0);
    if (!result) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << fname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", fname);
        return false;
    }
    if (swsort)
        lc->doSort(true);
    else
        lc->doSort(false);
    return true;
}


long int OptionContainer::findoptionI(const char *option)
{
    long int res = String(findoptionS(option).c_str()).toLong();
    return res;
}

std::string OptionContainer::findoptionS(const char *option)
{
    // findoptionS returns a found option stored in the deque
    String temp;
    String temp2;
    String o(option);

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
            return temp.toCharArray();
        }
    }
    return "";
}

std::deque<String> OptionContainer::findoptionM(const char *option)
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

bool OptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage)
{
    // realitycheck checks an amount for certain expected criteria
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


bool OptionContainer::loadDMPlugins()
{
    std::deque<String> dq = findoptionM("downloadmanager");
    unsigned int numplugins = dq.size();
    if (numplugins < 1) {
        if (!is_daemonised) {
            std::cerr << "There must be at least one download manager option" << std::endl;
        }
        syslog(LOG_ERR, "%s", "There must be at least one download manager option");
        return false;
    }
    String config;
    for (unsigned int i = 0; i < numplugins; i++) {
        config = dq[i];
#ifdef DGDEBUG
        std::cout << "loading download manager config: " << config << std::endl;
#endif
        DMPlugin *dmpp = dm_plugin_load(config.toCharArray());
        if (dmpp == NULL) {
            if (!is_daemonised) {
                std::cerr << "dm_plugin_load() returned NULL pointer with config file: " << config << std::endl;
            }
            syslog(LOG_ERR, "dm_plugin_load() returned NULL pointer with config file: %s", config.toCharArray());
            return false;
        }
        bool lastplugin = (i == (numplugins - 1));
        int rc = dmpp->init(&lastplugin);
        if (rc < 0) {
            if (!is_daemonised) {
                std::cerr << "Download manager plugin init returned error value: " << rc << std::endl;
            }
            syslog(LOG_ERR, "Download manager plugin init returned error value: %d", rc);
            return false;
        } else if (rc > 0) {
            if (!is_daemonised) {
                std::cerr << "Download manager plugin init returned warning value: " << rc << std::endl;
            }
            syslog(LOG_ERR, "Download manager plugin init returned warning value: %d", rc);
        }
        dmplugins.push_back(dmpp);
    }
    // cache reusable iterators
    dmplugins_begin = dmplugins.begin();
    dmplugins_end = dmplugins.end();
    return true;
}

bool OptionContainer::loadCSPlugins()
{
    std::deque<String> dq = findoptionM("contentscanner");
    unsigned int numplugins = dq.size();
    if (numplugins < 1) {
        return true; // to have one is optional
    }
    String config;
    for (unsigned int i = 0; i < numplugins; i++) {
        config = dq[i];
// worth adding some input checking on config
#ifdef DGDEBUG
        std::cout << "loading content scanner config: " << config << std::endl;
#endif
        CSPlugin *cspp = cs_plugin_load(config.toCharArray());
        if (cspp == NULL) {
            if (!is_daemonised) {
                std::cerr << "cs_plugin_load() returned NULL pointer with config file: " << config << std::endl;
            }
            syslog(LOG_ERR, "cs_plugin_load() returned NULL pointer with config file: %s", config.toCharArray());
            return false;
        }
#ifdef DGDEBUG
        std::cout << "Content scanner plugin is good, calling init..." << std::endl;
#endif
        int rc = cspp->init(NULL);
        if (rc < 0) {
            if (!is_daemonised) {
                std::cerr << "Content scanner plugin init returned error value: " << rc << std::endl;
            }
            syslog(LOG_ERR, "Content scanner plugin init returned error value: %d", rc);
            return false;
        } else if (rc > 0) {
            if (!is_daemonised) {
                std::cerr << "Content scanner plugin init returned warning value: " << rc << std::endl;
            }
            syslog(LOG_ERR, "Content scanner plugin init returned warning value: %d", rc);
        }
        csplugins.push_back(cspp);
    }
    // cache reusable iterators
    csplugins_begin = csplugins.begin();
    csplugins_end = csplugins.end();
    return true;
}

bool OptionContainer::loadAuthPlugins()
{
    // Assume no auth plugins need an upstream proxy query (NTLM, BASIC) until told otherwise
    auth_needs_proxy_query = false;

    std::deque<String> dq = findoptionM("authplugin");
    unsigned int numplugins = dq.size();
    if (numplugins < 1) {
        return true; // to have one is optional
    }
    String config;
    for (unsigned int i = 0; i < numplugins; i++) {
        config = dq[i];
// worth adding some input checking on config
#ifdef DGDEBUG
        std::cout << "loading auth plugin config: " << config << std::endl;
#endif
        AuthPlugin *app = auth_plugin_load(config.toCharArray());
        if (app == NULL) {
            if (!is_daemonised) {
                std::cerr << "auth_plugin_load() returned NULL pointer with config file: " << config << std::endl;
            }
            syslog(LOG_ERR, "auth_plugin_load() returned NULL pointer with config file: %s", config.toCharArray());
            return false;
        }
#ifdef DGDEBUG
        std::cout << "Auth plugin is good, calling init..." << std::endl;
#endif
        int rc = app->init(NULL);
        if (rc < 0) {
            if (!is_daemonised) {
                std::cerr << "Auth plugin init returned error value: " << rc << std::endl;
            }
            syslog(LOG_ERR, "Auth plugin init returned error value: %d", rc);
            return false;
        } else if (rc > 0) {
            if (!is_daemonised) {
                std::cerr << "Auth plugin init returned warning value: " << rc << std::endl;
            }
            syslog(LOG_ERR, "Auth plugin init returned warning value: %d", rc);
        }

        if (app->needs_proxy_query) {
            auth_needs_proxy_query = true;
#ifdef DGDEBUG
            std::cout << "Auth plugin relies on querying parent proxy" << std::endl;
#endif
        }
        authplugins.push_back(app);
    }
    // cache reusable iterators
    authplugins_begin = authplugins.begin();
    authplugins_end = authplugins.end();
    return true;
}


bool OptionContainer::createLists(int load_id)  {
    std::shared_ptr<LOptionContainer> temp (new LOptionContainer(load_id));
    if (temp->loaded_ok) {
        current_LOC = temp;
        return true;
    }
    return false;
}


std::shared_ptr<LOptionContainer> OptionContainer::currentLists()  {
    return current_LOC;
}
