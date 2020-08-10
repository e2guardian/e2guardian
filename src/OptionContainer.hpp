// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_OPTIONCONTAINER
#define __HPP_OPTIONCONTAINER

// INCLUDES

#include "FOptionContainer.hpp"
#include "DownloadManager.hpp"
#include "ContentScanner.hpp"
#include "String.hpp"
#include "HTMLTemplate.hpp"
#include "ListContainer.hpp"
#include "ListManager.hpp"
#include "LanguageContainer.hpp"
#include "ImageContainer.hpp"
#include "RegExp.hpp"
#include "Auth.hpp"
#include "IPList.hpp"
#include "Queue.hpp"
#include "LOptionContainer.hpp"
#include "DebugManager.hpp"
#include <deque>
#include <atomic>

#ifdef __SSLMITM
#include "CertificateAuthority.hpp"
#endif


// DECLARATIONS

class OptionContainer
{
    public:
    Queue<std::string>* log_Q;
    Queue<std::string>* RQlog_Q;
    Queue<LQ_rec> http_worker_Q;
    
#ifndef NEWDEBUG_OFF
    std::string debuglevel;
    std::string path_debuglevel;
    DebugManager * myDebug;
#endif

    struct auth_entry {
        int entry_id = 0;
        String entry_function;
    };

    // all our many, many options
    int filter_groups = 0;
    int log_exception_hits = 0;
    bool config_error = false;
    bool non_standard_delimiter;
    int log_file_format = 0;
    std::string log_header_value;
    std::string ident_header_value;
    int weighted_phrase_mode = 0; // PIP added in - not sure if still required
    bool show_weighted_found = false;
    bool show_all_weighted_found = false;   // logs weighted less than limit
    bool forwarded_for = false;
    bool use_custom_banned_image = false;
    std::string custom_banned_image_file;
    bool use_custom_banned_flash = false;
    std::string custom_banned_flash_file;
    bool reverse_lookups = false;
    bool reverse_client_ip_lookups = false;
    bool log_client_hostnames = false;
    bool use_xforwardedfor = false;
    std::deque<String> xforwardedfor_filter_ip;
    bool logconerror = false;
    bool logchildprocs = false;
    bool log_ssl_errors = false;
    bool log_client_host_and_ip = false;
    int url_cache_number = 0;
    int url_cache_age = 0;
    int phrase_filter_mode = 0;
    int preserve_case = 0;
    unsigned int max_header_lines = 0;
    int default_fg = 0;
    int default_trans_fg = 0;
    int default_icap_fg = 0;
    bool use_dash_for_blanks = true;
    bool hex_decode_content = false;
    bool force_quick_search = false;
    bool map_auth_to_ports = false;
    bool map_ports_to_ips = false;
    int filter_port = 0;
    int proxy_port = 0;
    bool no_proxy = false;
    int transparenthttps_port = 0;
    int icap_port = 0;
    std::string server_name;
    std::string icap_reqmod_url;
    std::string icap_resmod_url;
    std::string proxy_ip;
    std::deque<String> filter_ip;
    std::deque<String> check_ip;
    std::deque<String> filter_ports;
    std::map<int, String> auth_map;
    bool abort_on_missing_list = false;
    bool SB_trace = false;
#ifdef NOTDEF
    bool get_orig_ip = false;
#endif
    int ll = 0;
    int connect_timeout = 0;
    int connect_timeout_sec = 0;
    int connect_retries = 0;
    int proxy_timeout = 0;
    int proxy_timeout_sec = 0;
    int proxy_failure_log_interval = 0;
    int exchange_timeout = 0;
    int exchange_timeout_sec = 0;
    int pcon_timeout = 0;
    int pcon_timeout_sec = 0;
    int http_workers = 0;
    std::string daemon_user_name;
    std::string daemon_group_name;
    int proxy_user = 0;
    int proxy_group = 0;
    int root_user = 0;
    int max_ips = 0;
    bool recheck_replaced_urls;
    bool use_group_names_list = false;
    bool auth_needs_proxy_query = false;
    bool auth_requires_user_and_group = false;
    bool enable_ssl = false;
    bool auth_needs_proxy_in_plugin = false;
    bool use_original_ip_port = false;   // only for tranparent and no upstream proxy

    bool prefer_cached_lists = false;
    std::string languagepath;
    std::string filter_groups_list_location;
    //std::string banned_ip_list_location;
    //std::string exception_ip_list_location;
    std::string log_location;
    std::string RQlog_location;
    bool log_requests = false;
    std::string ipc_filename;
    std::string urlipc_filename;
    std::string ipipc_filename;
    std::string pid_filename;
    std::string blocked_content_store;
    std::string monitor_helper;
    bool monitor_helper_flag = false;
    std::string monitor_flag_prefix;
    bool monitor_flag_flag = false;
    std::string dstat_location;
    bool dstat_log_flag = false;
    bool stats_human_readable = false;
    int dstat_interval = 300;
    bool dns_user_logging = false;
    std::string dns_user_logging_domain;

    // Hardware/organisation/etc. IDs
    std::string logid_1;
    std::string logid_2;

    bool no_daemon = false;
    bool e2_front_log = false;
    bool no_logger = false;
    bool log_syslog = false;
    std::string name_suffix;
    unsigned int max_logitem_length = 2000;
    bool anonymise_logs = false;
    bool log_ad_blocks = false;
    bool log_timestamp = false;
    bool log_user_agent = false;
    bool soft_restart = false;

#ifdef __SSLMITM
    std::string ssl_certificate_path;
#endif

#ifdef __SSLMITM
    std::string ca_certificate_path;
    std::string ca_private_key_path;
    std::string cert_private_key_path;
    std::string generated_cert_path;
    std::string generated_link_path;
    std::string openssl_conf_path;
    CertificateAuthority *ca;
    bool use_openssl_conf = false;
    bool have_openssl_conf = false;
#endif
    std::string set_cipher_list;

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

    std::deque<auth_entry> auth_entry_dq;

    std::string daemon_user;
    std::string daemon_group;
    off_t max_content_filter_size;
    off_t max_content_ramcache_scan_size;
    off_t max_content_filecache_scan_size;
    bool scan_clean_cache = false;
    bool delete_downloaded_temp_files = false;
    bool search_sitelist_for_ip = false;
    std::string download_dir;
    int initial_trickle_delay = 0;
    int trickle_delay = 0;
    int content_scanner_timeout = 0;
    int content_scanner_timeout_sec = 0;

    HTMLTemplate html_template;
    ListContainer filter_groups_list;
    LanguageContainer language_list;
    ImageContainer banned_image;
    ImageContainer banned_flash;

    std::deque<Plugin *> dmplugins;
    std::deque<Plugin *> csplugins;
    std::deque<Plugin *> authplugins;
    std::deque<Plugin *>::iterator dmplugins_begin;
    std::deque<Plugin *>::iterator dmplugins_end;
    std::deque<Plugin *>::iterator csplugins_begin;
    std::deque<Plugin *>::iterator csplugins_end;
    std::deque<Plugin *>::iterator authplugins_begin;
    std::deque<Plugin *>::iterator authplugins_end;

    ListManager lm;
    int numfg = 0;

    // access denied domain (when using the CGI)
    String access_denied_domain;

    bool loadCSPlugins();
    bool loadAuthPlugins();
    void deletePlugins(std::deque<Plugin *> &list);
 //   void deleteFilterGroups();
  //  void deleteFilterGroupsJustListData();

    //...and the functions that read them

    OptionContainer();
    ~OptionContainer();
    bool read(std::string& filename, int type);
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
    std::string conffilename;
 //   std::string html_template_location;
    std::string group_names_list_location;
    int reporting_level = 0;

    private:
    std::deque<std::string> conffile;
    bool readConfFile(const char *filename, String &list_pwd);


    bool loadDMPlugins();

  //  bool precompileregexps();
    long int findoptionI(const char *option);
    std::string findoptionS(const char *option);
    bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
   // bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html);
    std::deque<String> findoptionM(const char *option);

//    bool inIPList(const std::string *ip, ListContainer &list, std::string *&host);
};

#endif
