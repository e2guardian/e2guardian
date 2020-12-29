// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_OPTIONCONTAINER
#define __HPP_OPTIONCONTAINER

// INCLUDES

#include "Auth.hpp"
#include "CertificateAuthority.hpp"
#include "ConfigReader.hpp"
#include "FOptionContainer.hpp"
#include "DownloadManager.hpp"
#include "ContentScanner.hpp"
#include "String.hpp"
#include "HTMLTemplate.hpp"
#include "ImageContainer.hpp"
#include "ListContainer.hpp"
#include "ListManager.hpp"
#include "LanguageContainer.hpp"
#include "LOptionContainer.hpp"
#include "RegExp.hpp"
#include "IPList.hpp"
#include "Queue.hpp"
#include <atomic>



// DECLARATIONS
struct BlockPageOptions
{
    int reporting_level = 0;

    bool use_custom_banned_image = false;
    std::string custom_banned_image_file;
    ImageContainer banned_image;

    bool use_custom_banned_flash = false;
    std::string custom_banned_flash_file;
    ImageContainer banned_flash;

};
struct CertificateOptions
{
    bool enable_ssl = false;

    std::string ssl_certificate_path;
    std::string ca_certificate_path;
    std::string ca_private_key_path;
    std::string cert_private_key_path;
    std::string generated_cert_path;
    std::string generated_link_path;
    std::string openssl_conf_path;
    CertificateAuthority *ca;

    time_t gen_cert_start, gen_cert_end;
    bool use_openssl_conf = false;
    bool have_openssl_conf = false;
    std::string set_cipher_list;

    bool generate_ca_certificate();
};
struct ConfigOptions 
{
    std::string prog_name;   // (default e2guardian)
    std::string configfile;  // Main Configfile (default e2guardian.conf)
    std::string conffilename;


    std::string languagepath;

    char benchmark = '\0';
    bool total_block_list = false;
};
struct ConnectionHandlerOptions {

    bool use_original_ip_port = false;   // only for transparent and no upstream proxy
    bool logconerror = false;

    bool reverse_client_ip_lookups = false;

    // internal test urls
    std::string internal_test_url;
    std::string internal_status_url;

};
struct ContentScannerOptions {
    
    bool contentscanning = false;

    off_t max_content_filter_size;
    off_t max_content_ramcache_scan_size;
    off_t max_content_filecache_scan_size;
    bool scan_clean_cache = false;              // Check: Not used?
    bool content_scan_exceptions = false;       // Check: Not used?  (There is another one in FOptionContainer)
    int initial_trickle_delay = 0;
    int trickle_delay = 0;
    int content_scanner_timeout = 0;
    int content_scanner_timeout_sec = 0;

    std::string download_dir;
    bool delete_downloaded_temp_files = false;
};
struct DStatOptions
{
    std::string dstat_location;
    bool dstat_log_flag = false;
    bool stats_human_readable = false;
    int dstat_interval = 300;
};
struct FilterGroupOptions
{
    int filter_groups = 0;
    int numfg = 0;
    int default_fg = 0;
    int default_trans_fg = 0;
    int default_icap_fg = 0;
    std::string filter_groups_list_location;
    ListContainer filter_groups_list;

};
struct HTTPHeaderOptions 
{
    std::string ident_header_value;
    bool forwarded_for = false;
    unsigned int max_header_lines = 0;

};
struct ListsOptions
{
    bool read_from_stdin = false;     // unused ?? kdg 22.12.2020
    bool force_quick_search = false;

};
struct LogOptions
{
    Queue<std::string>* log_Q;
    Queue<std::string>* RQlog_Q;

    //Queue<AccessLogger::LogRecord*> log_Q;
    //Queue<AccessLogger::LogRecord*> RQlog_Q;

    int log_level = 0;
    int log_file_format = 0;
    int log_exception_hits = 0;
    int debug_format = 1;

    bool log_client_hostnames = false;
    bool log_client_host_and_ip = false;  // TODO: unused ???
    bool anonymise_logs = false;
    bool log_ad_blocks = false;
    bool log_timestamp = false;
    bool log_user_agent = false;
    bool use_dash_for_blanks = true;
    bool SB_trace = false;

    unsigned int max_logitem_length = 2000;

    std::string dns_user_logging_domain;  // TODO: not documented ??
    bool dns_user_logging() { return !dns_user_logging_domain.empty(); };

    std::string log_header_value;

    // Hardware/organisation/etc. IDs
    std::string logid_1;
    std::string logid_2;

    std::string name_suffix;    // for SyslogName, where configured ??

};
struct NetworkOptions
{
    std::string server_name;

    std::string proxy_ip;
    bool no_proxy = ( proxy_ip == "");

    std::string TLSproxyCN;
    bool TLSproxyCN_is_ip = false;

    bool map_ports_to_ips = false;
    bool map_auth_to_ports = false;

    std::deque<String> filter_ip;
    std::deque<String> check_ip;
    std::deque<String> xforwardedfor_filter_ip;
    std::deque<String> filter_ports;
    std::deque<String> TLS_filter_ports;

    int filter_port = 0;
    int proxy_port = 0;
    int transparenthttps_port = 0;
    int icap_port = 0;

    int connect_timeout = 0;
    int connect_timeout_sec = 0;
    int connect_retries = 0;
    int proxy_timeout = 0;
    int proxy_timeout_sec = 0;
    int pcon_timeout = 0;
    int pcon_timeout_sec = 0;
    int exchange_timeout = 0;
    int exchange_timeout_sec = 0;

    int proxy_failure_log_interval = 0; // or  in LogOptions ??

    int number_of_fds_neded();
};
struct NaughtyOptions
{
    int phrase_filter_mode = 0;
    int weighted_phrase_mode = 0;   // PIP added in - not sure if still required (There is another on in FOption Container)
    bool show_weighted_found = false;
    bool show_all_weighted_found = false;   // logs weighted less than limit
    int preserve_case = 0;
    bool hex_decode_content = false;
};
struct ProcessOptions
{
    int root_user = 0;
    int proxy_user = 0;
    int proxy_group = 0;

    //std::string daemon_user;
    //std::string daemon_group;
    std::string daemon_user_name;
    std::string daemon_group_name;

    std::string pid_filename;

    int http_workers = 0;

    bool no_daemon = false;
    bool is_daemonised = false;

    bool find_user_ids();
    bool become_root_user();
    bool become_proxy_user();
    bool daemonise();           // Fork ourselves off into the background
};

class OptionContainer
{
    public:
    BlockPageOptions      block;
    CertificateOptions    cert;
    ConfigOptions         config;
    ConnectionHandlerOptions  conn;
    ContentScannerOptions content;
    DStatOptions          dstat;
    FilterGroupOptions    filter;
    HTTPHeaderOptions     header;
    ListsOptions          lists;
    LogOptions            log;
    NaughtyOptions        naughty;
    NetworkOptions        net;
    ProcessOptions        proc;


    Queue<LQ_rec> http_worker_Q;
    
    struct SB_entry_map {
        int entry_id = 0;
        String entry_function;
    };

    // all our many, many options
    bool config_error = false;
    //bool non_standard_delimiter;  // unused, but in FOptionContainer

    bool reverse_lookups = false;
    bool use_xforwardedfor = false;
    bool log_ssl_errors = false;
    int url_cache_number = 0;       // unused ??
    int url_cache_age = 0;          // unused ??

    std::string icap_reqmod_url;
    std::string icap_resmod_url;

    std::map<int, String> auth_map;
    bool abort_on_missing_list = false;
#ifdef NOTDEF
    bool get_orig_ip = false;
#endif

    int max_ips = 0;
    bool recheck_replaced_urls;
    bool use_group_names_list = false;
    bool auth_needs_proxy_query = false;
    bool auth_requires_user_and_group = false;
    bool auth_needs_proxy_in_plugin = false;

    std::string log_location;
    std::string RQlog_location;
    bool log_requests = false;
    std::string blocked_content_store;
    // std::string monitor_helper;
    // bool monitor_helper_flag = false;
    std::string monitor_flag_prefix;
    bool monitor_flag_flag = false;
    bool search_sitelist_for_ip = false;


    //bool soft_restart = false;

#ifdef ENABLE_EMAIL
    // Email notification patch by J. Gauthier
    std::string mailer;
#endif

    std::string storyboard_location;

    std::deque<String> iplist_dq;
    std::deque<String> sitelist_dq;
    std::deque<String> ipsitelist_dq;
    std::deque<String> urllist_dq;
    std::deque<String> regexpboollist_dq;
    std::deque<String> maplist_dq;
    std::deque<String> ipmaplist_dq;

    std::deque<SB_entry_map> auth_entry_dq;
    std::deque<SB_entry_map> dm_entry_dq;


    LanguageContainer language_list;
    HTMLTemplate html_template;
    ListManager lm;

    std::deque<Plugin *> dmplugins;
    std::deque<Plugin *> csplugins;
    std::deque<Plugin *> authplugins;
    std::deque<Plugin *>::iterator dmplugins_begin;
    std::deque<Plugin *>::iterator dmplugins_end;
    std::deque<Plugin *>::iterator csplugins_begin;
    std::deque<Plugin *>::iterator csplugins_end;
    std::deque<Plugin *>::iterator authplugins_begin;
    std::deque<Plugin *>::iterator authplugins_end;


    // access denied domain (when using the CGI)
    // String access_denied_domain; // Unused, see FOptionContainer/LOptionContainer 

    bool loadDMPlugins(ConfigReader &cr);
    bool loadCSPlugins(ConfigReader &cr);
    bool loadAuthPlugins(ConfigReader &cr);
    void deletePlugins(std::deque<Plugin *> &list);

    //   void deleteFilterGroups();
    //  void deleteFilterGroupsJustListData();

    //...and the functions that read them

    OptionContainer();
    ~OptionContainer();

    bool read_config(std::string& filename, int type);
    //bool readConfFile(const char *filename, String &list_pwd);
    void reset();

    //const char *inSiteList(String &url, ListContainer *lc, bool swsort, bool ip);
    //char *inURLList(String &url, ListContainer *lc, bool swsort, bool ip);

    //bool readStdin(ListContainer *lc, bool swsort, const char *listname );
    bool readinStdin();
  //  bool inTotalBlockList(String &url);
    std::string per_room_directory_location;
    bool createLists(int load_id);
    std::shared_ptr<LOptionContainer> currentLists();
    std::atomic<int> LC_cnt;

    //LOptionContainer* current_LOC;
    std::shared_ptr<LOptionContainer> current_LOC;
    //   std::string html_template_location;
    // std::string group_names_list_location;
    

    private:
    std::deque<std::string> conffile;


    // long int findoptionI(const char *option);
    // std::string findoptionS(const char *option);
    // std::deque<String> findoptionM(const char *option);

    bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
    // long int realitycheckWithDefault(const char * option, long int minl, long int maxl, long int defaultl);

    bool findAccessLogOptions(ConfigReader &cr);
    bool findBlockPageOptions(ConfigReader &cr);
    bool findCertificateOptions(ConfigReader &cr);
    bool findConfigOptions(ConfigReader &cr);
    bool findConnectionHandlerOptions(ConfigReader &cr);
    bool findContentScannerOptions(ConfigReader &cr);
    bool findDStatOptions(ConfigReader &cr);
    bool findFilterGroupOptions(ConfigReader &cr);
    bool findHeaderOptions(ConfigReader &cr);
    bool findListsOptions(ConfigReader &cr);
    bool findLoggerOptions(ConfigReader &cr);
    bool findNaughtyOptions(ConfigReader &cr);
    bool findNetworkOptions(ConfigReader &cr);
    bool findProcOptions(ConfigReader &cr);

   // bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html);
    std::deque<String> findoptionM(const char *option);
    std::deque<String> findoptionMD(const char *option, const char *delim);

};

#endif
