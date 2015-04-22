// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_OPTIONCONTAINER
#define __HPP_OPTIONCONTAINER


// INCLUDES

#include "DownloadManager.hpp"
#include "ContentScanner.hpp"
#include "String.hpp"
#include "HTMLTemplate.hpp"
#include "ListContainer.hpp"
#include "ListManager.hpp"
#include "FOptionContainer.hpp"
#include "LanguageContainer.hpp"
#include "ImageContainer.hpp"
#include "RegExp.hpp"
#include "Auth.hpp"
#include "IPList.hpp"

#include <deque>

#ifdef __SSLMITM
#include "CertificateAuthority.hpp"
#endif


// DECLARATIONS
	struct room_item { 
		std::string name; 
		IPList *iplist; 
		ListContainer *sitelist; 
		ListContainer *urllist; 
		bool block;
		bool part_block;
	};

class OptionContainer
{
public:
	// all our many, many options
	int filter_groups;
	int log_exception_hits;
	bool non_standard_delimiter;
	int log_file_format;
	int weighted_phrase_mode;  // PIP added in - not sure if still required
	bool show_weighted_found;
	bool forwarded_for;
	bool createlistcachefiles;
	bool use_custom_banned_image;
	std::string custom_banned_image_file;
	bool use_custom_banned_flash;
	std::string custom_banned_flash_file;
	bool reverse_lookups;
	bool reverse_client_ip_lookups;
	bool log_client_hostnames;
	bool use_xforwardedfor;
	bool logconerror;
	bool logchildprocs;
	int url_cache_number;
	int url_cache_age;
	int phrase_filter_mode;
	int preserve_case;
	bool hex_decode_content;
	bool force_quick_search;
	bool map_auth_to_ports;
	bool map_ports_to_ips;
	bool alive_with_proxy;
	int filter_port;
	int proxy_port;
	std::string proxy_ip;
	std::deque<String> filter_ip;
	std::deque<String> filter_ports;
	std::map<int, String> auth_map;
#ifdef ENABLE_ORIG_IP
	bool get_orig_ip;
#endif
	int ll;
	int max_children;
	int proxy_timeout;
	int exchange_timeout;
	int pcon_timeout;
	int min_children;
	int maxspare_children;
	int prefork_children;
	int minspare_children;
	int maxage_children;
	std::string daemon_user_name;
	std::string daemon_group_name;
	int proxy_user;
	int proxy_group;
	int root_user;
    	off_t max_upload_size;
	int max_ips;
	bool recheck_replaced_urls;
	bool use_filter_groups_list;
	bool use_group_names_list;
	bool auth_needs_proxy_query;
	bool total_block_site_flag;
	bool total_block_url_flag;

	bool prefer_cached_lists;
	std::string languagepath;
	std::string filter_groups_list_location;
	std::string access_denied_address;
	std::string sslaccess_denied_address;
	std::string log_location;
	std::string stat_location;
	std::string ipc_filename;
	std::string urlipc_filename;
	std::string ipipc_filename;
	std::string pid_filename;
	std::string blocked_content_store;

	// Hardware/organisation/etc. IDs
	std::string logid_1;
	std::string logid_2;

#ifdef SG_LOGFORMAT
	// Product ID
	std::string prod_id;
#endif

	bool no_daemon;
	bool no_logger;
	bool log_syslog;
	unsigned int max_logitem_length;
	bool anonymise_logs;
	bool log_ad_blocks;
	bool log_timestamp;
	bool log_user_agent;
	bool soft_restart;

#ifdef __SSLMITM
	std::string ssl_certificate_path;
#endif

#ifdef __SSLMITM
	std::string ca_certificate_path;
	std::string ca_private_key_path;
	std::string cert_private_key_path;
	std::string generated_cert_path;
	std::string generated_link_path;
	CertificateAuthority *ca;
#endif

#ifdef ENABLE_EMAIL
	// Email notification patch by J. Gauthier
	std::string mailer;   
#endif

	std::string daemon_user;
	std::string daemon_group;
	off_t max_content_filter_size;
	off_t max_content_ramcache_scan_size;
	off_t max_content_filecache_scan_size;
	bool scan_clean_cache;
	bool content_scan_exceptions;
	bool delete_downloaded_temp_files;
	std::string download_dir;
	int initial_trickle_delay;
	int trickle_delay;
	int content_scanner_timeout;

	HTMLTemplate html_template;
	ListContainer filter_groups_list;
	IPList exception_ip_list;
	IPList banned_ip_list;
	LanguageContainer language_list;
	ImageContainer banned_image;
	ImageContainer banned_flash;

	std::deque<Plugin*> dmplugins;
	std::deque<Plugin*> csplugins;
	std::deque<Plugin*> authplugins;
	std::deque<Plugin*>::iterator dmplugins_begin;
	std::deque<Plugin*>::iterator dmplugins_end;
	std::deque<Plugin*>::iterator csplugins_begin;
	std::deque<Plugin*>::iterator csplugins_end;
	std::deque<Plugin*>::iterator authplugins_begin;
	std::deque<Plugin*>::iterator authplugins_end;

	ListManager lm;
	FOptionContainer **fg;
	int numfg;

	// access denied domain (when using the CGI)
	String access_denied_domain;
	String sslaccess_denied_domain;

	bool loadCSPlugins();
	bool loadAuthPlugins();
	void deletePlugins(std::deque<Plugin*> &list);
	void deleteFilterGroups();
	void deleteFilterGroupsJustListData();

	//...and the functions that read them

	OptionContainer();
	~OptionContainer();
	bool read(const char *filename, int type);
	void reset();
	bool inExceptionIPList(const std::string *ip, std::string *&host);
	bool inBannedIPList(const std::string *ip, std::string *&host);
	bool readFilterGroupConf();
	// public so fc_controlit can reload filter group config files
	bool doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort);

	// per-room blocking and URL whitelisting: see if given IP is in a room; if it is, return true and put the room name in "room"
	bool inRoom(const std::string& ip, std::string& room, std::string *&host, bool* block, bool* part_block, bool* isexception, String url) ;
	void loadRooms();
	void deleteRooms();

	char *inSiteList(String &url,ListContainer *lc, bool swsort, bool ip);
	char *inURLList(String &url,ListContainer *lc, bool swsort, bool ip);

	bool readStdin(ListContainer *lc, bool swsort, const char *listname, const char *startstr);
	bool readinStdin();
	bool inTotalBlockList(String &url);
	bool use_total_block_list;

private:
	std::string per_room_directory_location;
	std::deque<std::string> conffile;
	String conffilename;
	int reporting_level;

	std::string html_template_location;
	std::string group_names_list_location;

	bool loadDMPlugins();

	bool precompileregexps();
	long int findoptionI(const char *option);
	std::string findoptionS(const char *option);
	bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
	bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html);
	std::deque<String> findoptionM(const char *option);

	bool inIPList(const std::string *ip, ListContainer& list, std::string *&host);
	std::list<room_item> rooms;
};

#endif
