// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
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
extern thread_local std::string thread_id;



//ListContainer total_block_site_list;
//ListContainer total_block_url_list;

// IMPLEMENTATION

OptionContainer::OptionContainer() {
    log_Q = new Queue<std::string>;
    RQlog_Q = new Queue<std::string>;
    // http_worker_Q = new Queue<LQ_rec>;
}


OptionContainer::~OptionContainer() {
    reset();
}

void OptionContainer::reset() {
    //deleteFilterGroups();
    deletePlugins(dmplugins);
    deletePlugins(csplugins);
    deletePlugins(authplugins);
    //deleteRooms();
    //exception_ip_list.reset();
    //banned_ip_list.reset();
    language_list.reset();
    conffile.clear();
    filter_ip.clear();
    filter_ports.clear();
    auth_map.clear();
}


void OptionContainer::deletePlugins(std::deque<Plugin *> &list) {
    for (std::deque<Plugin *>::iterator i = list.begin(); i != list.end(); i++) {
        if ((*i) != NULL) {
            (*i)->quit();
            delete (*i);
        }
    }
    list.clear();
}


bool OptionContainer::readConfFile(const char *filename, String &list_pwd) {
    std::string linebuffer;
    String temp; // for tempory conversion and storage
    String now_pwd(list_pwd);
    std::ifstream conffiles(filename, std::ios::in); // e2guardianfN.conf
    if (!conffiles.good()) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error reading: " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error reading %s", filename);
        return false;
    }
    String base_dir(filename);
    base_dir.baseDir();

    while (!conffiles.eof()) {
        getline(conffiles, linebuffer);
        if (!conffiles.fail() && linebuffer.length() != 0) {
            if (linebuffer[0] != '#') { // i.e. not commented out
                temp = (char *) linebuffer.c_str();
                if (temp.contains("#")) {
                    temp = temp.before("#");
                }
                temp.removeWhiteSpace(); // get rid of spaces at end of line
                while (temp.contains("__LISTDIR__")) {
                    String temp2 = temp.before("__LISTDIR__");
                    temp2 += now_pwd;
                    temp2 += temp.after("__LISTDIR__");
                    temp = temp2;
                }
                // deal with included files
                if (temp.startsWith(".")) {
                    temp = temp.after(".Include<").before(">");
                    if (temp.length() > 0) {
                        temp.fullPath(base_dir);
                        if (!readConfFile(temp.toCharArray(), now_pwd)) {
                            conffiles.close();
                            return false;
                        }
                    }
                    String temp2 = temp.after(".Define LISTDIR <").before(">");
                    if (temp2.length() > 0) {
                        now_pwd = temp2;
                        //if(!now_pwd.endsWith("/"))
                        //    now_pwd += "/";
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

bool OptionContainer::read(std::string &filename, int type) {
    conffilename = filename;

    // all sorts of exceptions could occur reading conf files
    try {
        String list_pwd = __CONFDIR;
        list_pwd += "/lists/common";
        if (!readConfFile(filename.c_str(), list_pwd))
            return false;

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
            } else if ((log_location = findoptionS("loglocation")) == "") {
                log_location = __LOGLOCATION;
                log_location += "/access.log";
                log_syslog = false;
            }
#ifndef NEWDEBUG_OFF
            if ((debuglevel = findoptionS("debuglevel")) != "") {

            }
            if ((path_debuglevel = findoptionS("debuglevelfile")) != "") {

            }
            myDebug = new DebugManager(debuglevel, path_debuglevel);
#endif
            if ((RQlog_location = findoptionS("rqloglocation")) == "") {
                log_requests = false;
            } else {
                log_requests = true;
            }

            if ((dstat_location = findoptionS("dstatlocation")) == "") {
                dstat_log_flag = false;
            } else {
                dstat_log_flag = true;
                dstat_interval = findoptionI("dstatinterval");
                if (dstat_interval == 0) {
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

        if (findoptionS("nodaemon") == "on") {
            no_daemon = true;
        } else {
            no_daemon = false;
        }

        if (findoptionS("dockermode") == "on") {
            no_daemon = true;
            e2_front_log = true;
        } else {
            no_daemon = false;
            e2_front_log = false;
        }

        if (findoptionS("nologger") == "on") {
            no_logger = true;
        } else {
            no_logger = false;
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
    if (findoptionS("useopensslconf") == "on") {
        use_openssl_conf = true;
        openssl_conf_path = findoptionS("opensslconffile");
        if (openssl_conf_path == "") {
            have_openssl_conf = false;
        } else {
            have_openssl_conf = true;
        }
    } else {
        use_openssl_conf = false;
    };

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

        monitor_helper = findoptionS("monitorhelper");
        if (monitor_helper == "") {
            monitor_helper_flag = false;
        } else {
            monitor_helper_flag = true;
        }

        server_name = findoptionS("servername");
        if (server_name == "") {
            char sysname[256];
            int r;
            r = gethostname(sysname, 256);
            if (r == 0) {
                server_name = sysname;
            }
        }

        max_header_lines = findoptionI("maxheaderlines");
        if (max_header_lines == 0)
            max_header_lines = 50;
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

        connect_timeout_sec = findoptionI("connecttimeout");
        if (connect_timeout_sec == 0)
            connect_timeout_sec = 5;
        if (!realitycheck(connect_timeout_sec, 1, 100, "connecttimeout")) {
            return false;
        } // check its a reasonable value
        connect_timeout = connect_timeout_sec * 1000;

        connect_retries = findoptionI("connectretries");
        if (connect_retries == 0)
            connect_retries = 1;
        if (!realitycheck(connect_retries, 1, 100, "connectretries")) {
            return false;
        } // check its a reasonable value


        proxy_timeout_sec = findoptionI("proxytimeout");
        if (proxy_timeout_sec == 0) proxy_timeout_sec = 55;
        if (!realitycheck(proxy_timeout_sec, 5, 100, "proxytimeout")) {
            return false;
        } // check its a reasonable value
        proxy_timeout = proxy_timeout_sec * 1000;

        pcon_timeout_sec = findoptionI("pcontimeout");
        if (pcon_timeout_sec == 0) pcon_timeout_sec = 55;
        if (!realitycheck(pcon_timeout_sec, 5, 300, "pcontimeout")) {
            return false;
        } // check its a reasonable value
        pcon_timeout = pcon_timeout_sec * 1000;

        exchange_timeout_sec = findoptionI("proxyexchange");
        if (exchange_timeout_sec == 0) exchange_timeout_sec = 61;
        if (!realitycheck(exchange_timeout_sec, 5, 300, "proxyexchange")) {
            return false;
        }
        exchange_timeout = exchange_timeout_sec * 1000;

        if (findoptionS("httpworkers").empty()) {
            http_workers = 500;
        } else {
            http_workers = findoptionI("httpworkers");
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
            max_content_filter_size = 2048;
        }

        max_content_filter_size *= 1024;

        if(findoptionS("maxcontentramcachescansize").empty()) {
            max_content_filecache_scan_size = 2000;
        } else {
            max_content_ramcache_scan_size = findoptionI("maxcontentramcachescansize");
        }
        if (!realitycheck(max_content_ramcache_scan_size, 0, 0, "maxcontentramcachescansize")) {
            return false;
        }
        max_content_ramcache_scan_size *= 1024;

        max_content_filecache_scan_size = findoptionI("maxcontentfilecachescansize");
        if (!realitycheck(max_content_filecache_scan_size, 0, 0, "maxcontentfilecachescansize")) {
            return false;
        }
        if (max_content_filecache_scan_size == 0) {
            max_content_filecache_scan_size = 20000;
        }
        max_content_filecache_scan_size *= 1024;

        if (max_content_ramcache_scan_size == 0) {
            max_content_ramcache_scan_size = max_content_filecache_scan_size;
        }
        if ( findoptionS("weightedphrasemode").empty()) {
            weighted_phrase_mode = 2;
        } else {
            weighted_phrase_mode = findoptionI("weightedphrasemode");
        }
        if (!realitycheck(weighted_phrase_mode, 0, 2, "weightedphrasemode")) {
            return false;
        }

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
                    std::cerr << "maxcontentramcachescansize can not be greater than maxcontentfilecachescansize"
                              << std::endl;
                }
                syslog(LOG_ERR, "%s", "maxcontentramcachescansize can not be greater than maxcontentfilecachescansize");
                return false;
            }

            trickle_delay = findoptionI("trickledelay");
            if (trickle_delay == 0) {
                trickle_delay = 10;
            }
            if (!realitycheck(trickle_delay, 1, 0, "trickledelay")) {
                return false;
            }
            initial_trickle_delay = findoptionI("initialtrickledelay");
            if (initial_trickle_delay == 0) {
                initial_trickle_delay = 20;
            }
            if (!realitycheck(initial_trickle_delay, 1, 0, "initialtrickledelay")) {
                return false;
            }

            content_scanner_timeout_sec = findoptionI("contentscannertimeout");
            if (content_scanner_timeout_sec == 0) content_scanner_timeout_sec = 60;
            if (!realitycheck(content_scanner_timeout_sec, 1, 0, "contentscannertimeout")) {
                return false;
            }

            if (content_scanner_timeout_sec > 0)
                content_scanner_timeout = content_scanner_timeout_sec * 1000;
            else {
                content_scanner_timeout = pcon_timeout;
                content_scanner_timeout_sec = pcon_timeout_sec;
            }

        }

        if (findoptionS("deletedownloadedtempfiles") == "off") {
            delete_downloaded_temp_files = false;
        } else {
            delete_downloaded_temp_files = true;
        }

        if (findoptionS("searchsitelistforip"
                        "") == "off") {
            search_sitelist_for_ip = false;
        } else {
            search_sitelist_for_ip = true;
        }

        if (findoptionS("phrasefiltermode").empty()) {
            phrase_filter_mode = 2;
        } else {
            phrase_filter_mode = findoptionI("phrasefiltermode");
        }
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

        if (findoptionS("mapportstoips") == "on") {  // to be removed in v5.5
            map_ports_to_ips = true;
        } else {
            map_ports_to_ips = false;
        }

        if (findoptionS("mapauthtoports") == "on") {  // to be removed in v5.5
            map_auth_to_ports = true;
        } else {
            map_auth_to_ports = false;
        }

        if (findoptionS("usecustombannedimage") == "off") {
            use_custom_banned_image = false;
        } else {
            use_custom_banned_image = true;
            custom_banned_image_file = findoptionS("custombannedimagefile");
            if (custom_banned_image_file.empty()) {
                custom_banned_image_file = __DATADIR;
                custom_banned_image_file += "/transparent1x1.gif";
            }
            banned_image.read(custom_banned_image_file.c_str());
        }

        if (findoptionS("usecustombannedflash") == "off") {
            use_custom_banned_flash = false;
        } else {
            use_custom_banned_flash = true;
            custom_banned_flash_file = findoptionS("custombannedflashfile");

            if (custom_banned_flash_file.empty()) {
                custom_banned_flash_file = __DATADIR;
                custom_banned_flash_file += "/blockedflash.swf";
            }
            banned_flash.read(custom_banned_flash_file.c_str());
        }

        proxy_ip = findoptionS("proxyip");
        if (proxy_ip == "")
            no_proxy = true;
        else
            no_proxy = false;

        if (!no_proxy) {
            proxy_port = findoptionI("proxyport");
            if(proxy_port == 0) proxy_port = 3128;
            if (!realitycheck(proxy_port, 1, 65535, "proxyport")) {
                return false;
            } // etc
        }

        // multiple listen IP support
        filter_ip = findoptionM("filterip");
        if( filter_ip.empty()) filter_ip.push_back("");
        if (filter_ip.size() > 127) {
            if (!is_daemonised) {
                std::cerr << "Can not listen on more than 127 IPs" << std::endl;
            }
            syslog(LOG_ERR, "%s", "Can not listen on more than 127 IPs");
            return false;
        }
        // multiple check IP support - used for loop checking
        check_ip = findoptionM("checkip");
        if (check_ip.size() > 127) {
            if (!is_daemonised) {
                std::cerr << "Can not check on more than 127 IPs" << std::endl;
            }
            syslog(LOG_ERR, "%s", "Can not check on more than 127 IPs");
            return false;
        }
        if (check_ip.empty()) {
                String t = "127.0.0.1";
                check_ip.push_back(t);
        }

        filter_ports = findoptionM("filterports");
        if (filter_ports.empty())
            filter_ports.push_back("8080");
        if (map_ports_to_ips and filter_ports.size() != filter_ip.size()) {
            if (!is_daemonised) {
                std::cerr << "filterports (" << filter_ports.size() << ") must match number of filterips ("
                          << filter_ip.size() << ")" << std::endl;
            }
            syslog(LOG_ERR, "%s", "filterports must match number of filterips");
            return false;
        }
        filter_port = filter_ports[0].toInteger();
        if (!realitycheck(filter_port, 1, 65535, "filterport[0]")) {
            return false;
        } // check its a reasonable value

        transparenthttps_port = findoptionI("transparenthttpsport");
        if (!realitycheck(transparenthttps_port, 0, 65535, "transparenthttpsport")) {
            return false;
        } // check its a reasonable value

        icap_port = findoptionI("icapport");
        if (!realitycheck(filter_port, 0, 65535, "icapport")) {
            return false;
        } // check its a reasonable value

        if (icap_port > 0) {   // add non-plugin auth for ICAP
            auth_entry sen;
            sen.entry_function = "auth_icap";
            sen.entry_id = ENT_STORYA_AUTH_ICAP;
            auth_entry_dq.push_back(sen);
        }

        icap_reqmod_url = findoptionS("icapreqmodurl");
        if (icap_reqmod_url == "")
            icap_reqmod_url = "request";

        icap_resmod_url = findoptionS("icapresmodurl");
        if (icap_resmod_url == "")
            icap_resmod_url = "response";

        if (findoptionS("useoriginalip") == "off") {
            use_original_ip_port = false;
        } else {
            use_original_ip_port = true;
        }

        if(findoptionS("loglevel").empty()) {
            ll = 3;
        } else {
            ll = findoptionI("loglevel");
        }
        if (!realitycheck(ll, 0, 3, "loglevel")) {
            return false;
        } // etc
        log_file_format = findoptionI("logfileformat");
        if(log_file_format == 0) log_file_format = 8;
        if (!realitycheck(log_file_format, 1, 8, "logfileformat")) {
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
        if (findoptionS("usedashforblank") == "off") {
            use_dash_for_blanks = false;
        } else {
            use_dash_for_blanks = true;
        }
        if (findoptionS("logclientnameandip") == "off") {
            log_client_host_and_ip = false;
        } else {
            log_client_host_and_ip = true;
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

        if (findoptionS("showweightedfound") == "off") {
            show_weighted_found = false;
        } else {
            show_weighted_found = true;
        }
        if (findoptionS("showallweightedfound") == "on") {
            show_all_weighted_found = true;
            show_weighted_found = true;
        } else {
            show_all_weighted_found = false;
        }
        if(findoptionS("reportinglevel").empty()) {
            reporting_level = 3;
        } else {
            reporting_level = findoptionI("reportinglevel");
        }
        if (!realitycheck(reporting_level, -1, 3, "reportinglevel")) {
            return false;
        }
        String t = findoptionS("languagedir") + "/" ;
        if (t == "/") {
            t = __DATADIR;
            t += "/languages";
        }
        languagepath = t;
        languagepath += "/";
        languagepath += findoptionS("language") + "/";

        if (findoptionS("forwardedfor") == "on") {
            forwarded_for = true;
        } else {
            forwarded_for = false;
        }
        if (findoptionS("addforwardedfor") == "on") {
            forwarded_for = true;
        }
        if (findoptionS("logexceptionhits").empty()) {
            log_exception_hits = 2;
        } else {
            log_exception_hits = findoptionI("logexceptionhits");
        }
        if (!realitycheck(log_exception_hits, 0, 2, "logexceptionhits")) {
            return false;
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
            reverse_client_ip_lookups = true;
        } else {
            log_client_hostnames = false;
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
        if (filter_groups == 0) filter_groups = 1;

        default_fg = findoptionI("defaultfiltergroup");
        if (default_fg > 0) {
            if (default_fg <= filter_groups) {
                default_fg--;
            } else {
                syslog(LOG_ERR, "defaultfiltergroup out of range");
                return false;
            }
        }

        default_trans_fg = findoptionI("defaulttransparentfiltergroup");
        if (default_trans_fg > 0) {
            if (default_trans_fg <= filter_groups) {
                default_trans_fg--;
            } else {
                syslog(LOG_ERR, "defaulttransparentfiltergroup out of range");
                return false;
            }
        }

        default_icap_fg = findoptionI("defaulticapfiltergroup");
        if (default_icap_fg > 0) {
            if (default_icap_fg <= filter_groups) {
                default_icap_fg--;
            } else {
                syslog(LOG_ERR, "defaulticapfiltergroup out of range");
                return false;
            }
        }

        if (findoptionS("abortiflistmissing") == "on") {
            abort_on_missing_list = true;
        } else {
            abort_on_missing_list = false;
        }

        if (findoptionS("storyboardtrace") == "on") {
            SB_trace = true;
        } else {
            SB_trace = false;
        }

        storyboard_location = findoptionS("preauthstoryboard");
        if (storyboard_location.empty()) {
            storyboard_location = __CONFDIR;
            storyboard_location += "/preauth.story";


        }

        per_room_directory_location = findoptionS("perroomdirectory");

        if (!realitycheck(filter_groups, 1, 0, "filtergroups")) {
            return false;
        }
        if (filter_groups < 1) {
            if (!is_daemonised) {
                std::cerr << "filtergroups too small" << std::endl;
            }
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
        if (download_dir.empty()) {
            download_dir = "/tmp";
        }

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
        for (unsigned int i = 0; i < authplugins.size(); i++) {
            AuthPlugin *tmpPlugin = (AuthPlugin *) authplugins[i];
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
            while (it != authplugins.end()) {
                AuthPlugin *tmp = (AuthPlugin *) *it;
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

        // if there's no auth enabled, we only need the first group's settings - THIS IS NO LONGER THE CASE TRANs, ICAP canbe set to different defaults
        //if (authplugins.size() == 0)
        //    filter_groups = 1;
        numfg = filter_groups;

        //filter_groups_list_location = findoptionS("filtergroupslist");
        //     banned_ip_list_location = findoptionS("bannediplist");
        group_names_list_location = findoptionS("groupnamesfile");
        std::string language_list_location(languagepath + "messages");
        iplist_dq = findoptionM("iplist");
        sitelist_dq = findoptionM("sitelist");
        ipsitelist_dq = findoptionM("ipsitelist");
        urllist_dq = findoptionM("urllist");
        regexpboollist_dq = findoptionM("regexpboollist");
        maplist_dq = findoptionM("maplist");
        ipmaplist_dq = findoptionM("ipmaplist");

        if ((findoptionS("authrequiresuserande2roup") == "on") && (authplugins.size() > 1))
            auth_requires_user_and_group = true;

        if (group_names_list_location.length() == 0) {
            use_group_names_list = false;
#ifdef E2DEBUG
            std::cout << "Not using groupnameslist" << std::endl;
#endif
        } else {
            use_group_names_list = true;
        }


        if (!language_list.readLanguageList(language_list_location.c_str())) {
            return false;
        } // messages language file



#ifdef _SSLMITM
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


bool OptionContainer::readinStdin() {
    if (!std::cin.good()) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error reading stdin: " << std::endl;
        }
        syslog(LOG_ERR, "Error reading stdin");
        return false;
    }
    std::string linebuffer;
    String temp;
    while (!std::cin.eof()) {
        //   std::cerr << "wiating for stdin" << std::endl;
        getline(std::cin, linebuffer);
        //    std::cerr << "Line in: " << linebuffer << std::endl;
        if (linebuffer.length() < 2)
            continue; // its jibberish

        temp = linebuffer.c_str();
        bool site_list = false;
        bool url_list = false;
        if (linebuffer[0] == '#') {
            if (temp.startsWith("#SITELIST:"))
                site_list = true;
            else if (temp.startsWith("#URLLIST:"))
                url_list = true;
            else
                continue;
            String param = temp.after(":");
            String nm, fpath;
            String t = param;
            bool startswith;
            t.removeWhiteSpace();
            t += ",";
            while (t.length() > 0) {
                if (t.startsWith("name=")) {
                    nm = t.after("=").before(",");
                } else if (t.startsWith("path=")) {
                    fpath = t.after("=").before(",");
                }
                t = t.after(",");
            }
            if (!fpath.startsWith("memory:")) {
                // syntax error
                return false;
            }
            if (nm.length() == 0) {
                // syntax error
                return false;
            }
            if (site_list)
                startswith = false;
            else
                startswith = true;

            int rc = lm.newItemList(fpath.c_str(), "", startswith, 1, true);
            if (rc < 0)
                return false;
            lm.l[rc]->doSort(url_list);
            if (site_list)
                sitelist_dq.push_back(param);
            else
                urllist_dq.push_back(param);
        }
    }
    return true;
}


long int OptionContainer::findoptionI(const char *option) {
    long int res = String(findoptionS(option).c_str()).toLong();
    return res;
}

std::string OptionContainer::findoptionS(const char *option) {
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

std::deque<String> OptionContainer::findoptionM(const char *option) {
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

bool OptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage) {
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


bool OptionContainer::loadDMPlugins() {
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
#ifdef E2DEBUG
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

bool OptionContainer::loadCSPlugins() {
    std::deque<String> dq = findoptionM("contentscanner");
    unsigned int numplugins = dq.size();
    if (numplugins < 1) {
        return true; // to have one is optional
    }
    String config;
    for (unsigned int i = 0; i < numplugins; i++) {
        config = dq[i];
// worth adding some input checking on config
#ifdef E2DEBUG
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
#ifdef E2DEBUG
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

bool OptionContainer::loadAuthPlugins() {
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
#ifdef E2DEBUG
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
#ifdef E2DEBUG
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
#ifdef E2DEBUG
            std::cout << "Auth plugin relies on querying parent proxy" << std::endl;
#endif
        }
        if (app->needs_proxy_access_in_plugin) {
            auth_needs_proxy_in_plugin = true;
#ifdef E2DEBUG
            std::cout << "Auth plugin relies on querying parent proxy within plugin" << std::endl;
#endif
        }
        authplugins.push_back(app);
    }
    // cache reusable iterators
    authplugins_begin = authplugins.begin();
    authplugins_end = authplugins.end();
    return true;
}


bool OptionContainer::createLists(int load_id) {
    std::shared_ptr<LOptionContainer> temp(new LOptionContainer(load_id));
    if (temp->loaded_ok) {
        current_LOC = temp;
        return true;
    }
    return false;
}


std::shared_ptr<LOptionContainer> OptionContainer::currentLists() {
    return current_LOC;
}
