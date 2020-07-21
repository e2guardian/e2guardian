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
#include "Logger.hpp"
#include "LoggerConfigurator.hpp"

//#include <iostream>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <cstdlib>
#include <unistd.h> 
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <sys/stat.h>

// GLOBALS


// IMPLEMENTATION

OptionContainer::OptionContainer() {
    //log.log_Q = new Queue<AccessLogger::LogRecord>;
    //log.RQlog_Q = new Queue<AccessLogger::LogRecord>;
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
    net.filter_ip.clear();
    net.filter_ports.clear();
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
    LoggerConfigurator loggerConf(&e2logger);

    std::ifstream inputfile(filename, std::ios::in); // e2guardian.conf or e2guardianfN.conf
    if (!inputfile.good()) {
        e2logger_error("Error reading ", filename);
        return false;
    }
    String base_dir(filename);
    base_dir.baseDir();

    while (!inputfile.eof()) {
        getline(inputfile, linebuffer);
        if (!inputfile.fail() && linebuffer.length() != 0) {
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
                            inputfile.close();
                            return false;
                        }
                    }
                    String temp2 = temp.after(".Define LISTDIR <").before(">");
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

                if (temp.startsWith(LoggerConfigurator::PREFIX))
                    loggerConf.configure(temp);

                linebuffer = temp.toCharArray();
                e2logger_config("read:", linebuffer);
                conffile.push_back(linebuffer); // stick option in deque
            }
        }
    }
    inputfile.close();
    return true;
}

bool OptionContainer::readConfig(std::string &filename, bool reload) {
    conffilename = filename;

    // all sorts of exceptions could occur reading conf files
    try {
        String list_pwd;
        if (!readConfFile(filename.c_str(), list_pwd))
            return false;

        if (!findProcOptions()) return false;
        if (!findLogOptions()) return false;
        if (!findDStatOptions()) return false;

        if (reload) return true;

        if (!findCertificateOptions()) return false;
        if (!findNetworkOptions()) return false;
        if (!findConnectionOptions()) return false;
        if (!findNaughtyOptions()) return false;
        if (!findContentScannerOptions()) return false;




        blocked_content_store = findoptionS("blockedcontentstore");
	
        soft_restart = (findoptionS("softrestart") == "on");


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


        max_header_lines = findoptionI("maxheaderlines");
        if (max_header_lines == 0)
            max_header_lines = 40;
        if (!realitycheck(max_header_lines, 10, 250, "maxheaderlines")) {
            return false;
        }


        if (net.icap_port > 0) {   // add non-plugin auth for ICAP
            SB_entry_map sen;
            sen.entry_function = "auth_icap";
            sen.entry_id = ENT_STORYA_AUTH_ICAP;
            auth_entry_dq.push_back(sen);
        }


        http_workers = findoptionI("httpworkers");
        if (http_workers == 0) {
		    http_workers = 100;
            e2logger_error("http_workers settings cannot be zero: value set to 100");
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

        
        /*
		if ((weighted_phrase_mode != 0)) {
			max_content_filter_size = max_content_ramcache_scan_size;
			if (max_content_filter_size == 0) {
				e2logger_error("maxcontent* settings cannot be zero (to disable phrase filtering, set weightedphrasemode to 0)");
				return false;
			}
		}
*/

        if (findoptionS("searchsitelistforip"
                        "") == "off") {
            search_sitelist_for_ip = false;
        } else {
            search_sitelist_for_ip = true;
        }

        url_cache_number = findoptionI("urlcachenumber");
        if (!realitycheck(url_cache_number, 0, 0, "urlcachenumber")) {
            return false;
        }

        url_cache_age = findoptionI("urlcacheage");
        if (!realitycheck(url_cache_age, 0, 0, "urlcacheage")) {
            return false;
        }



        if (findoptionS("mapauthtoports") == "off") {
            map_auth_to_ports = false;
        } else {
            map_auth_to_ports = true;
        }




        icap_reqmod_url = findoptionS("icapreqmodurl");
        if (icap_reqmod_url == "")
            icap_reqmod_url = "request";

        icap_resmod_url = findoptionS("icapresmodurl");
        if (icap_resmod_url == "")
            icap_resmod_url = "response";



        lists.force_quick_search = (findoptionS("forcequicksearch") == "on");


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
        if (!realitycheck(filter_groups, 1, 0, "filtergroups")) {
            return false;
        }
        if (filter_groups < 1) {
            e2logger_error("filtergroups too small");
            return false;
        }


        default_fg = findoptionI("defaultfiltergroup");
        if (default_fg > 0) {
            if (default_fg <= filter_groups) {
                default_fg--;
            } else  {
                e2logger_error("defaultfiltergroup out of range");
                return false;
            }
        }

        default_trans_fg = findoptionI("defaulttransparentfiltergroup");
        if (default_trans_fg > 0) {
            if (default_trans_fg <= filter_groups) {
                default_trans_fg--;
            } else  {
                e2logger_error("defaulttransparentfiltergroup out of range");
                return false;
            }
        }

        default_icap_fg = findoptionI("defaulticapfiltergroup");
        if (default_icap_fg > 0) {
            if (default_icap_fg <= filter_groups) {
                default_icap_fg--;
            } else  {
                e2logger_error("defaulticapfiltergroup out of range");
                return false;
            }
        }

        if (findoptionS("abortiflistmissing") == "on") {
            abort_on_missing_list = true;
        } else {
            abort_on_missing_list = false;
        }

        if (findoptionS("storyboardtrace") == "on")
        {
            SB_trace = true;
        } else {
            SB_trace = false;
        }

        storyboard_location = findoptionS("preauthstoryboard");
        if (storyboard_location == "")
            e2logger_error("Missing preauthstoryboard in: ", filename);

        if (((per_room_directory_location = findoptionS("perroomdirectory")) != "") ||
            ((per_room_directory_location = findoptionS("perroomblockingdirectory")) != "")) {
            //loadRooms(true);
        }


        if (!loadDMPlugins()) {
            e2logger_error("Error loading DM plugins");
            return false;
        }

        if (content.contentscanning) {
            if (!loadCSPlugins()) {
                e2logger_error("Error loading CS plugins");
                return false;
            }
        }

        if (!loadAuthPlugins()) {
            e2logger_error("Error loading auth plugins");
            return false;
        }

        // check if same number of auth-plugin as ports if in
        //     authmaptoport mode
        if (map_auth_to_ports && (net.filter_ports.size() > 1)
            && (net.filter_ports.size() != authplugins.size())) {
            e2logger_error("In mapauthtoports mode you need to setup one port per auth plugin");
            return false;
        }

        // map port numbers to auth plugin names
        for (unsigned int i = 0; i < authplugins.size(); i++) {
            AuthPlugin *tmpPlugin = (AuthPlugin *) authplugins[i];
            String tmpStr = tmpPlugin->getPluginName();

            if ((!map_auth_to_ports) || net.filter_ports.size() == 1)
                auth_map[i] = tmpStr;
            else
                auth_map[net.filter_ports[i].toInteger()] = tmpStr;
        }

        // if the more than one port is being used, validate the combination of auth plugins
        if (authplugins.size() > 1 and net.filter_ports.size() > 1 and map_auth_to_ports) {
            std::deque<Plugin *>::iterator it = authplugins.begin();
            String firstPlugin;
            while (it != authplugins.end()) {
                AuthPlugin *tmp = (AuthPlugin *) *it;
                if (tmp->getPluginName().startsWith("proxy-basic")) {
                    e2logger_error("Proxy auth is not possible with multiple ports");
                    return false;
                }
                if (tmp->getPluginName().startsWith("proxy-ntlm") && (tmp->isTransparent() == false)) {
                    e2logger_error("Non-transparent NTLM is not possible with multiple ports");
                    return false;
                }
                if (it == authplugins.begin())
                    firstPlugin = tmp->getPluginName();
                else {
                    if ((firstPlugin == tmp->getPluginName()) and (!tmp->getPluginName().startsWith("ssl-core"))) {
                        e2logger_error("Auth plugins can not be the same");
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
            e2logger_debug("Not using groupnameslist");
        } else {
            use_group_names_list = true;
        }


        if (!language_list.readLanguageList(language_list_location.c_str())) {
            return false;
        } // messages language file

        if (cert.enable_ssl && !cert.start_ssl()) return false;        

    } catch (std::exception &e) {
        e2logger_error(e.what());
        return false;
    }
    e2logger_config("Done: read Configfile: ", filename);
    return true;
}


bool OptionContainer::readinStdin()
{
    e2logger_trace("");
    
    if (!std::cin.good()) {
        e2logger_error("Error reading stdin");
        return false;
    }
    std::string linebuffer;
    String temp;
    while (!std::cin.eof()) {
        getline(std::cin, linebuffer);
        e2logger_debug("Line in: ", linebuffer);
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


bool OptionContainer::findCertificateOptions()
{
    cert.enable_ssl = (findoptionS("enablessl") == "on");

    cert.ssl_certificate_path = findoptionS("sslcertificatepath") + "/";
    if (cert.ssl_certificate_path == "/") {
        cert.ssl_certificate_path = ""; // "" will enable default openssl certs
    }

    if(cert.enable_ssl) {
        bool ret = true;

        if (findoptionS("useopensslconf") == "on") {
            cert.use_openssl_conf = true;
            cert.openssl_conf_path = findoptionS("opensslconffile");
            cert.have_openssl_conf = (cert.openssl_conf_path != "");
        } else {
            cert.use_openssl_conf = false;
        };

        cert.ca_certificate_path = findoptionS("cacertificatepath");
        if (cert.ca_certificate_path == "") {
            e2logger_error("cacertificatepath is required when ssl is enabled");
            ret = false;
        }

        cert.ca_private_key_path = findoptionS("caprivatekeypath");
        if (cert.ca_private_key_path == "") {
            e2logger_error("caprivatekeypath is required when ssl is enabled");
            ret = false;
        }

        cert.cert_private_key_path = findoptionS("certprivatekeypath");
        if (cert.cert_private_key_path == "") {
            e2logger_error("certprivatekeypath is required when ssl is enabled");
            ret = false;
        }

        cert.generated_cert_path = findoptionS("generatedcertpath") + "/";
        if (cert.generated_cert_path == "/") {
            e2logger_error("generatedcertpath is required when ssl is enabled");
            ret = false;
        }

        time_t def_start = 1417872951; // 6th Dec 2014
        time_t ten_years = 315532800;
        cert.gen_cert_start = findoptionI("generatedcertstart");
        if (cert.gen_cert_start < def_start)
            cert.gen_cert_start = def_start;
        cert.gen_cert_end = findoptionI("generatedcertend");
        if (cert.gen_cert_end < cert.gen_cert_start)
            cert.gen_cert_end = cert.gen_cert_start + ten_years;

        cert.set_cipher_list = findoptionS("setcipherlist");
        if (cert.set_cipher_list == "")
            cert.set_cipher_list = "HIGH:!ADH:!MD5:!RC4:!SRP:!PSK:!DSS";

        if (ret) {
#ifdef NODEF
            ca = new CertificateAuthority(ca_certificate_path.c_str(),
            ca_private_key_path.c_str(),
            cert_private_key_path.c_str(),
            generated_cert_path.c_str(),
            gen_cert_start, gen_cert_end);
#endif
        } else {
           return false;
        }
    }
    return true;

}
bool OptionContainer::findConnectionOptions()
{
    conn.use_custom_banned_image = (findoptionS("usecustombannedimage") != "off");
    if (conn.use_custom_banned_image)
    {
        conn.custom_banned_image_file = findoptionS("custombannedimagefile");
        conn.banned_image.read(conn.custom_banned_image_file.c_str());
    }

    conn.use_custom_banned_flash = (findoptionS("usecustombannedflash") != "off");
    if (conn.use_custom_banned_image)
    {
        conn.custom_banned_flash_file = findoptionS("custombannedflashfile");
        conn.banned_flash.read(conn.custom_banned_flash_file.c_str());
    }

    conn.use_original_ip_port = (findoptionS("useoriginalip") == "on");

    return true;
}
bool OptionContainer::findContentScannerOptions()
{

    content.contentscanning = findoptionM("contentscanner").size() > 0;

    content.max_content_filecache_scan_size = realitycheckWithDefault("maxcontentfilecachescansize", 0, 0, 20000 );
    content.max_content_filecache_scan_size *= 1024;

    content.max_content_ramcache_scan_size = realitycheckWithDefault("maxcontentramcachescansize", 0, 0, 2000);
    content.max_content_ramcache_scan_size *= 1024;
    if (content.max_content_ramcache_scan_size == 0) {
        content.max_content_ramcache_scan_size = content.max_content_filecache_scan_size;
    }

    content.max_content_filter_size = realitycheckWithDefault("maxcontentfiltersize", 1, 0, content.max_content_ramcache_scan_size );
    content.max_content_filter_size *= 1024;
    if (content.max_content_filter_size == 0) {
        content.max_content_filter_size = content.max_content_ramcache_scan_size;
    }

    if (content.contentscanning) {

        if (content.max_content_filter_size > content.max_content_ramcache_scan_size) {
            e2logger_error("maxcontentfiltersize can not be greater than maxcontentramcachescansize");
            return false;
        }
        if (content.max_content_ramcache_scan_size > content.max_content_filecache_scan_size) {
            e2logger_error("maxcontentramcachescansize can not be greater than maxcontentfilecachescansize");
            return false;
        }

        content.trickle_delay = realitycheckWithDefault("trickledelay", 1, 0, 10);
        content.initial_trickle_delay = realitycheckWithDefault("initialtrickledelay", 1, 0, 20);

        content.content_scanner_timeout_sec = realitycheckWithDefault("contentscannertimeout", 1, 0, 60);
        if (content.content_scanner_timeout_sec > 0)
            content.content_scanner_timeout *= 1000;
        else {
            content.content_scanner_timeout = net.peercon_timeout;
            content.content_scanner_timeout_sec = net.peercon_timeout_sec;
        }

        // KDG: not documented??
        content.scan_clean_cache =  (findoptionS("scancleancache") != "off");
        // KDG moved to FOptionContainer ??
        content.content_scan_exceptions = (findoptionS("contentscanexceptions") == "on");
    }

    // this needs to be known before loading CS plugins,
    // because ClamAV plugin makes use of it during init()
    content.download_dir = findoptionS("filecachedir");
    content.delete_downloaded_temp_files = (findoptionS("deletedownloadedtempfiles") != "off");

    return true;
}
bool OptionContainer::findDStatOptions()
{
    if ((dstat.dstat_location = findoptionS("dstatlocation")) == "") {
        dstat.dstat_log_flag = false;
    } else {
        dstat.dstat_log_flag = true;
        dstat.dstat_interval = findoptionI("dstatinterval");
        if (dstat.dstat_interval == 0) {
            dstat.dstat_interval = 300; // 5 mins
        }
    }

    dstat.stats_human_readable =  (findoptionS("statshumanreadable") == "on");

    if ((stat_location = findoptionS("statlocation")) == "") {
        stat_location = std::string(__LOGLOCATION) + "/stats";
    }

    return true;
}
bool OptionContainer::findLogOptions()
{
    e2logger_trace("");

    log.dns_user_logging_domain = findoptionS("dnsuserloggingdomain");
    log.log_header_value = findoptionS("logheadervalue");

    // default of unlimited no longer allowed as could cause buffer overflow
    log.max_logitem_length = realitycheckWithDefault("maxlogitemlength", 10, 32000, 2000);

    log.log_level = realitycheckWithDefault("loglevel", 0, 3, 3);
    log.log_file_format = realitycheckWithDefault("logfileformat", 1, 8, 1);

    log.anonymise_logs = (findoptionS("anonymizelogs") == "on") ;
    log.log_ad_blocks = (findoptionS("logadblocks") == "on");
    log.log_timestamp = (findoptionS("logtimestamp") == "on");
    log.log_user_agent = (findoptionS("loguseragent") == "on");
    log.use_dash_for_blanks = (findoptionS("usedashforblank") == "off");
    log.log_client_host_and_ip = (findoptionS("logclientnameandip") == "off");

    log.log_exception_hits = realitycheckWithDefault("logexceptionhits", 0, 2, 2);

    log.log_client_hostnames = (findoptionS("logclienthostnames") == "on");
    reverse_client_ip_lookups = log.log_client_hostnames;  // TODO: reverse_client_ip_lookups could be don in log thread

    log.logid_1 = findoptionS("logid1");
    if (log.logid_1.empty())
        log.logid_1 = "-";
    log.logid_2 = findoptionS("logid2");
    if (log.logid_2.empty())
        log.logid_2 = "-";

    return true;
}
bool OptionContainer::findNaughtyOptions()
{
    naughty.weighted_phrase_mode = realitycheckWithDefault("weightedphrasemode", 0, 2, 0);

    naughty.phrase_filter_mode = realitycheckWithDefault("phrasefiltermode", 0, 3, 2);

    naughty.preserve_case = realitycheckWithDefault("preservecase", 0, 2, 0);

    naughty.hex_decode_content =  (findoptionS("hexdecodecontent") == "on");

    naughty.show_weighted_found = (findoptionS("showweightedfound") == "on");
    naughty.show_all_weighted_found = (findoptionS("showallweightedfound") == "on");
    if (naughty.show_all_weighted_found ) {
        naughty.show_weighted_found = true;
    }
    return true;
}
bool OptionContainer::findNetworkOptions()
{
    net.server_name = findoptionS("servername");
    if (net.server_name == "") {
        char sysname[256];
        int r;
        r = gethostname(sysname, 256);
        if (r == 0) {
            net.server_name = sysname;
        }
    }

    net.connect_timeout_sec =  realitycheckWithDefault("connecttimeout", 1, 100, 3);
    net.connect_timeout = net.connect_timeout_sec * 1000;
    net.connect_retries = realitycheckWithDefault("connectretries", 1, 100, 5);

    net.proxy_ip = findoptionS("proxyip");
    if (!net.no_proxy) {
        net.proxy_port = realitycheckWithDefault("proxyport", 1, 65535, 8080);
    }

    net.proxy_timeout_sec = realitycheckWithDefault("proxytimeout", 5, 100, 5);
    net.proxy_timeout = net.proxy_timeout_sec * 1000;
    net.proxy_failure_log_interval = realitycheckWithDefault("proxyfailureloginterval", net.proxy_timeout_sec, 3600, 600);

    net.peercon_timeout_sec = realitycheckWithDefault("pcontimeout", 5, 300, 5);
    net.peercon_timeout = net.peercon_timeout_sec * 1000;

    net.exchange_timeout_sec = realitycheckWithDefault("proxyexchange", 5, 300, 5);
    net.exchange_timeout = net.exchange_timeout_sec * 1000;

    net.map_ports_to_ips = !(findoptionS("mapportstoips") == "off");

    // multiple listen IP support
    net.filter_ip = findoptionM("filterip");
    if (net.filter_ip.size() > 127) {
        e2logger_error("Can not listen on more than 127 IPs");
        return false;
    }
    // multiple check IP support - used for loop checking
    net.check_ip = findoptionM("checkip");
    if (net.check_ip.size() > 127) {
        e2logger_error("Can not check on more than 127 IPs");
        return false;
    }

    net.filter_ports = findoptionM("filterports");
    if (net.map_ports_to_ips and net.filter_ports.size() != net.filter_ip.size()) {
        e2logger_error("filterports (", net.filter_ports.size(), ") must match number of filterips (", net.filter_ip.size(), ")");
        return false;
    }
    net.filter_port = net.filter_ports[0].toInteger();
    if (!realitycheck(net.filter_port, 1, 65535, "filterport[0]")) {
        return false;
    }

    net.transparenthttps_port = findoptionI("transparenthttpsport");
    if (!realitycheck(net.transparenthttps_port, 0, 65535, "transparenthttpsport")) {
        return false;
    }

    net.icap_port = findoptionI("icapport");
    if (!realitycheck(net.icap_port, 0, 65535, "icapport")) {
        return false;
    }


}
bool OptionContainer::findProcOptions()
{

    proc.no_daemon = (findoptionS("nodaemon") == "on");

    if (findoptionS("dockermode") == "on") {
        proc.no_daemon = true;
        e2logger.setDockerMode();
    }

    if ((proc.pid_filename = findoptionS("pidfilename")) == "") {
        proc.pid_filename = std::string(__PIDDIR) + "/e2guardian.pid";
    }

    if ((proc.daemon_user_name = findoptionS("daemonuser")) == "") {
        proc.daemon_user_name = __PROXYUSER;
    }

    if ((proc.daemon_group_name = findoptionS("daemongroup")) == "") {
        proc.daemon_group_name = __PROXYGROUP;
    }
    return true;

}



long int OptionContainer::findoptionI(const char *option) {
    std::string s = findoptionS(option);
    return String(s).toLong();
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
            e2logger_config(o, "=", temp);
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
            e2logger_config(o, "=" ,temp);
            results.push_back(temp);
        }
    }
    return results;
}

bool OptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage) {
    // realitycheck checks an amount for certain expected criteria
    // so we can spot problems in the conf files easier
    if ((l < minl) || ((maxl > 0) && (l > maxl))) {
        e2logger_error("Config problem; check allowed values for ", emessage, "( ", l , " should be >= ", minl, " <=", maxl, ")");
        return false;
    }
    return true;
}

long int OptionContainer::realitycheckWithDefault(const char *option, long int minl, long int maxl, long int defaultl) {
    // realitycheck checks an amount for certain expected criteria
    // so we can spot problems in the conf files easier    
    std::string s = findoptionS(option);
    if ( s == "" ) return defaultl;
    long int value = String(s).toLong();

    if ((value < minl) || ((maxl > 0) && (value > maxl))) {
        e2logger_error("Config problem; check allowed values for ", option, "( ", value , " should be >= ", minl, " <=", maxl, ")",
                    "we are using default value:", defaultl);        
        return defaultl;
    }
    return value;
}


bool OptionContainer::loadDMPlugins()
{
    e2logger_config("load Download manager plugins");
    std::deque<String> dq = findoptionM("downloadmanager");
    unsigned int numplugins = dq.size();
    if (numplugins < 1) {
        e2logger_error("There must be at least one download manager option");
        return false;
    }
    String config;
    for (unsigned int i = 0; i < numplugins; i++) {
        config = dq[i];
        e2logger_debug("loading download manager config: ", config);
        DMPlugin *dmpp = dm_plugin_load(config.toCharArray());
        if (dmpp == NULL) {
            e2logger_error("dm_plugin_load() returned NULL pointer with config file: ", config);
            return false;
        }
        bool lastplugin = (i == (numplugins - 1));
        int rc = dmpp->init(&lastplugin);
        if (rc < 0) {
            e2logger_error("Download manager plugin init returned error value: ", rc);
            return false;
        } else if (rc > 0) {
            e2logger_error("Download manager plugin init returned warning value: ", rc);
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
    e2logger_config("load Content scanner plugins");
    std::deque<String> dq = findoptionM("contentscanner");
    unsigned int numplugins = dq.size();
    if (numplugins < 1) {
        return true; // to have one is optional
    }
    String config;
    for (unsigned int i = 0; i < numplugins; i++) {
        config = dq[i];
        // worth adding some input checking on config
        e2logger_debug("loading content scanner config: ", config);
        CSPlugin *cspp = cs_plugin_load(config.toCharArray());
        if (cspp == NULL) {
            e2logger_error("cs_plugin_load() returned NULL pointer with config file: ", config);
            return false;
        }
        e2logger_debug("Content scanner plugin is good, calling init...");
        int rc = cspp->init(NULL);
        if (rc < 0) {
            e2logger_error("Content scanner plugin init returned error value: ", rc);
            return false;
        } else if (rc > 0) {
            e2logger_error("Content scanner plugin init returned warning value: ", rc);
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
    e2logger_config("load Auth plugins");
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
        e2logger_debug("loading auth plugin config: ", config);
        AuthPlugin *app = auth_plugin_load(config.toCharArray());
        if (app == NULL) {
            e2logger_error("auth_plugin_load() returned NULL pointer with config file: ", config);
            return false;
        }
        e2logger_debug("Auth plugin is good, calling init...");
        int rc = app->init(NULL);
        if (rc < 0) {
            e2logger_error("Auth plugin init returned error value:", rc);
            return false;
        } else if (rc > 0) {
            e2logger_error("Auth plugin init returned warning value: ", rc);
        }

        if (app->needs_proxy_query) {
            auth_needs_proxy_query = true;
            e2logger_debug("Auth plugin relies on querying parent proxy");
        }
        if (app->needs_proxy_access_in_plugin) {
            auth_needs_proxy_in_plugin = true;
            e2logger_debug("Auth plugin relies on querying parent proxy within plugin");
        }
        authplugins.push_back(app);
    }
    // cache reusable iterators
    authplugins_begin = authplugins.begin();
    authplugins_end = authplugins.end();
    return true;
}


bool OptionContainer::createLists(int load_id)  {
    e2logger_config("create Lists: ", load_id);
    std::shared_ptr<LOptionContainer> temp (new LOptionContainer(load_id));
    if (temp->loaded_ok) {
        current_LOC = temp;
        return true;
    }
    return false;
}

#pragma region ProcessOptions

bool ProcessOptions::find_user_ids()
{

    struct passwd *st;
    struct group *sg;
    int rc;

    root_user = geteuid();

    // "daemongroup" option exists, but never used to be honoured. this is now
    // an important feature, however, because we need to be able to create temp
    // files with suitable permissions for scanning by AV daemons - we do this
    // by becoming a member of a specified AV group and setting group read perms
    if ((sg = getgrnam(daemon_group_name.c_str())) != 0) {
        proxy_group = sg->gr_gid;
    } else {
        e2logger_error( "Unable to getgrnam(): ", strerror(errno));
        e2logger_error("Check the group that e2guardian runs as (", daemon_group_name, ")");
        return 1;
    }

    if ((st = getpwnam(daemon_user_name.c_str())) != 0) { // find uid for proxy user
        proxy_user = st->pw_uid;

        rc = setgid(proxy_group); // change to rights of proxy user group
        // i.e. low - for security
        if (rc == -1) {
            e2logger_error("Unable to setgid()");
            return false; // setgid failed for some reason so exit with error
        }


    } else {
        e2logger_error("Unable to getpwnam() - does the proxy user exist?");
        e2logger_error("Proxy user looking for is '", daemon_user_name, "'" );
        return false;   // was unable to lockup the user id from passwd
                        // for some reason, so exit with error
    }
    return true;
}

bool ProcessOptions::become_root_user()
{
    int rc;
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t)-1, root_user);
#else
    rc = seteuid(root_user);
#endif
    if (rc == -1) {
        e2logger_error("Unable to seteuid() to become root user");
        return false;
    }
    return true;
}

bool ProcessOptions::become_proxy_user()
{
    int rc;
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t)-1, proxy_user);
#else
    rc = seteuid(proxy_user); // become low priv again
#endif
    if (rc == -1) {
        e2logger_error("Unable to re-seteuid() to become proxy user");
        return false;
    }
    return true;
}

// Fork ourselves off into the background
bool ProcessOptions::daemonise()
{
    if (no_daemon) {
        return true;
    }
#ifdef E2DEBUG
    return true; // if debug mode is enabled we don't want to detach
#endif

    if (is_daemonised) {
        return true; // we are already daemonised so this must be a
        // reload caused by a HUP
    }

    int nullfd = -1;
    if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1) {
        e2logger_error("Couldn't open /dev/null");
        return false;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {    // Error!!
        close(nullfd);
        return false;
    } else if (pid != 0) {      // parent goes...
        if (nullfd != -1) {
            close(nullfd);
        }
        
        exit(0);    // bye-bye
    }

    // child continues
    dup2(nullfd, 0); // stdin
    dup2(nullfd, 1); // stdout
    dup2(nullfd, 2); // stderr
    close(nullfd);

    setsid(); // become session leader
    if (chdir("/") != 0) {// change working directory
	    e2logger_error(" Can't change / directory !");
	    return false;
    }
    umask(0); // clear our file mode creation mask
    umask(S_IWGRP | S_IWOTH); // set to mor sensible setting??

    is_daemonised = true;

    return true;
}
#pragma endregion

#pragma region NetOptions

int NetworkOptions::number_of_fds_neded() 
{
    if (map_ports_to_ips) {
        return filter_ip.size();
    } else {
        return filter_ports.size() * filter_ip.size();
    }
}

#pragma endregion

#pragma region  CertificateOptions
bool CertificateOptions::start_ssl()
{
    if (!enable_ssl) return true;

    e2logger_config("enable SSL");
    if (ca_certificate_path != "") {
        ca = new CertificateAuthority(ca_certificate_path.c_str(),
                                        ca_private_key_path.c_str(),
                                        cert_private_key_path.c_str(),
                                        generated_cert_path.c_str(),
                                        gen_cert_start, gen_cert_end);
        return true;
    } else {
        e2logger_error("Error - Valid cacertificatepath, caprivatekeypath and generatedcertpath must given when using MITM.");
        return false;
    }
}
#pragma endregion

std::shared_ptr<LOptionContainer> OptionContainer::currentLists() {
    return current_LOC;
}
