// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LOPTIONCONTAINER
#define __HPP_LOPTIONCONTAINER

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
#include "Queue.hpp"

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

class LOptionContainer
{
    public:
    Queue<std::string>* log_Q;
    Queue<Socket*>* http_worker_Q;

    // all our many, many options

    std::string name_suffix;

    HTMLTemplate html_template;
    ListContainer filter_groups_list;
    IPList exception_ip_list;
    IPList banned_ip_list;

    ListManager lm;
    FOptionContainer **fg;
    bool loaded_ok;
    int reload_id;
    int numfg;

    // access denied domain (when using the CGI)
    String access_denied_domain;
    String sslaccess_denied_domain;

    void deleteFilterGroups();
    void deleteFilterGroupsJustListData();

    //...and the functions that read them

    LOptionContainer();
    LOptionContainer(int reload_id);
    ~LOptionContainer();
    bool read(std::string& filename, int type, std::string& exception_ip_list_location,
              std::string& banned_ip_list_location);
    void reset();
    bool inExceptionIPList(const std::string *ip, std::string *&host);
    bool inBannedIPList(const std::string *ip, std::string *&host);
    bool readFilterGroupConf();
    // public so fc_controlit can reload filter group config files
    bool doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort);

    // per-room blocking and URL whitelisting: see if given IP is in a room; if it is, return true and put the room name in "room"
    bool inRoom(const std::string &ip, std::string &room, std::string *&host, bool *block, bool *part_block, bool *isexception, String url);
    void loadRooms(bool throw_error);
    void deleteRooms();

    char *inSiteList(String &url, ListContainer *lc, bool swsort, bool ip);
    char *inURLList(String &url, ListContainer *lc, bool swsort, bool ip);


    private:
    std::string per_room_directory_location;
    std::deque<std::string> conffile;
    std::string conffilename;
    int reporting_level;

    std::string html_template_location;
    std::string group_names_list_location;


    bool precompileregexps();
    long int findoptionI(const char *option);
    std::string findoptionS(const char *option);
    bool realitycheck(long int l, long int minl, long int maxl, const char *emessage);
    bool readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html);
    std::deque<String> findoptionM(const char *option);

    bool inIPList(const std::string *ip, ListContainer &list, std::string *&host);
    std::list<room_item> rooms;
};

#endif
