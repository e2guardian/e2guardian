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
#include "LogTransfer.hpp"


// DECLARATIONS
struct AccessLogOptions
{
    std::string log_location;
    std::string RQlog_location;
    std::string RSlog_location;
    std::string ALlog_location;

    Queue<LogTransfer*>* log_Q;
    Queue<LogTransfer*>* RQlog_Q;

    //Queue<AccessLogger::LogRecord*> log_Q;
    //Queue<AccessLogger::LogRecord*> RQlog_Q;

    int log_level = 0;
    int log_file_format = 0;
    LogFormat access_log_format;
    LogFormat request_log_format;
    //LogFormat response_log_format;   // not implimented response take access_log_format

    int log_exception_hits = 0;

    bool log_requests = false;
    bool log_responses = false;
    bool log_alerts = false;
    bool log_client_hostnames = false;
    bool log_client_host_and_ip = false;  // todo: unused - this IS used - PP
    bool anonymise_logs = false;
    bool log_ad_blocks = false;
    bool log_timestamp = false;
    bool log_user_agent = false;
    bool use_dash_for_blanks = true;
    unsigned int max_logitem_length = 2000;

    std::string dns_user_logging_domain;  // TODO: not documented ??
    bool dns_user_logging() { return !dns_user_logging_domain.empty(); };

    // Hardware/organisation/etc. IDs
    std::string logid_1;
    std::string logid_2;
    std::string prod_id;    // not used?? Is it needed for logs?? - Yes is in OptionContainer - option to add in logs
};

struct AuthPluginOptions 
{
    bool auth_requires_user_and_group = false;

    std::map<int, String> auth_map;
};
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
    std::string configfile;  // Main Configfile (default ${e2sysconfdir}/e2guardian.conf)
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
    bool use_group_names_list = false;  // Never set ?!?!

    std::string filter_groups_list_location;
    ListContainer filter_groups_list;

};
struct HTTPHeaderOptions 
{
    std::string ident_header_value;
    bool forwarded_for = false;
    unsigned int max_header_lines = 0;

};
struct ICAPOptions
{
    std::string icap_reqmod_url;
    std::string icap_resmod_url;
};
struct ListsOptions
{
    bool read_from_stdin = false;     // unused ?? kdg 22.12.2020
    bool force_quick_search = false;
    bool abort_on_missing_list = false;
    bool search_sitelist_for_ip = false;

    std::deque<String> iplist_dq;
    std::deque<String> sitelist_dq;
    std::deque<String> ipsitelist_dq;
    std::deque<String> urllist_dq;
    std::deque<String> regexpboollist_dq;
    std::deque<String> maplist_dq;
    std::deque<String> ipmaplist_dq;

};
struct LoggerOptions
{
    int debug_format = 1;

    bool log_ssl_errors = false;
    bool SB_trace = false;
    int  udp_source_port = 39000;

    std::string name_suffix;    // for SyslogName, where configured ??

};
struct MonitorOptions
{
    std::string monitor_flag_prefix;
    bool monitor_flag_flag = false;
};    
struct NetworkOptions
{
    std::string server_name;

    std::string proxy_ip;
    bool no_proxy = true;

    std::string TLSproxyCN;
    bool TLSproxyCN_is_ip = false;

    std::deque<String> filter_ip;
    std::deque<String> check_ip;
    std::deque<String> xforwardedfor_filter_ip;
    std::deque<String> filter_ports;
    std::deque<String> check_ports;
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
struct PluginOptions
{
    std::deque<Plugin *> dmplugins;
    std::deque<Plugin *> csplugins;
    std::deque<Plugin *> authplugins;
    std::deque<Plugin *>::iterator dmplugins_begin;
    std::deque<Plugin *>::iterator dmplugins_end;
    std::deque<Plugin *>::iterator csplugins_begin;
    std::deque<Plugin *>::iterator csplugins_end;
    std::deque<Plugin *>::iterator authplugins_begin;
    std::deque<Plugin *>::iterator authplugins_end;

    bool loadDMPlugins(ConfigReader &cr);
    bool loadCSPlugins(ConfigReader &cr);
    bool loadAuthPlugins(ConfigReader &cr);

    void deletePlugins(std::deque<Plugin *> &list);

    AuthPluginOptions   auth;     // for Auth Plugin
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
    bool is_dockermode = false;

    bool find_user_ids();
    bool become_root_user();
    bool become_proxy_user();
    bool daemonise();           // Fork ourselves off into the background
};
struct StoryBoardOptions
{
    struct SB_entry_map {
        int entry_id = 0;
        String entry_function;
    };

    std::string storyboard_location;  // better: preauth_location ??

    std::deque<SB_entry_map> auth_entry_dq;
    std::deque<SB_entry_map> dm_entry_dq;

    bool reverse_lookups = false;

};    

class OptionContainer
{
    public:
    // all our many, many options
    AccessLogOptions        log;
    BlockPageOptions        block;
    CertificateOptions      cert;
    ConfigOptions           config;
    ConnectionHandlerOptions  conn;
    ContentScannerOptions   content;
    DStatOptions            dstat;
    FilterGroupOptions      filter;
    HTTPHeaderOptions       header;
    ICAPOptions             icap;
    ListsOptions            lists;
    LoggerOptions           logger;
    MonitorOptions          monitor;
    NaughtyOptions          naughty;
    NetworkOptions          net;
    PluginOptions           plugins;
    ProcessOptions          proc;
    StoryBoardOptions       story;

    LanguageContainer       language_list;
    ListManager             lm;

    Queue<LQ_rec> http_worker_Q;

    bool config_error = false;

    bool use_xforwardedfor = false;

#ifdef ENABLE_EMAIL
    // Email notification patch by J. Gauthier
    std::string mailer;
#endif

  //  HTMLTemplate html_template; // unused ?? never set, not mentioned in e2guardian.conf but used in FOptionContainer::getHTMLTemplate

    std::string per_room_directory_location;  // todo: not used but in LOptionContainer ??

    OptionContainer();
    ~OptionContainer();

    bool read_config(const Path &filename, bool readFullConfig=true);
    void reset();

    bool readinStdin();

    bool createLists(int load_id);

    std::atomic<int> LC_cnt;
    std::shared_ptr<LOptionContainer> current_LOC;
    std::shared_ptr<LOptionContainer> currentLists();
    

    private:

    bool findAccessLogOptions(ConfigReader &cr);
    bool findBlockPageOptions(ConfigReader &cr);
    bool findCertificateOptions(ConfigReader &cr);
    bool findConfigOptions(ConfigReader &cr);
    bool findConnectionHandlerOptions(ConfigReader &cr);
    bool findContentScannerOptions(ConfigReader &cr);
    bool findDStatOptions(ConfigReader &cr);
    bool findFilterGroupOptions(ConfigReader &cr);
    bool findHeaderOptions(ConfigReader &cr);
    bool findICAPOptions(ConfigReader &cr);
    bool findListsOptions(ConfigReader &cr);
    bool findLoggerOptions(ConfigReader &cr);
    bool findMonitorOptions(ConfigReader &cr);
    bool findNaughtyOptions(ConfigReader &cr);
    bool findNetworkOptions(ConfigReader &cr);
    bool findPluginOptions(ConfigReader &cr);
    bool findProcOptions(ConfigReader &cr);
    bool findStoryBoardOptions(ConfigReader &cr);

    bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
   // bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html);   

};

#endif
