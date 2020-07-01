// ListMeta  - super-class for both item and phrase lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LISTMETA
#define __HPP_LISTMETA

// INLCUDES

#include <vector>
#include <deque>
#include <map>
#include <string>
#include "String.hpp"
#include "RegExp.hpp"
#include "ListContainer.hpp"

#define LIST_TYPE_IP                                            1
#define LIST_TYPE_SITE                                       2
#define LIST_TYPE_IPSITE                                    3
#define LIST_TYPE_URL                                       4
#define LIST_TYPE_SEARCH                                5
#define LIST_TYPE_REGEXP_BOOL                   6
#define LIST_TYPE_REGEXP_REP                       7
#define LIST_TYPE_PHRASE_BANNED               8
#define LIST_TYPE_PHRASE_WEIGHTED          9
#define LIST_TYPE_PHRASE_EXCEPTION       10
#define LIST_TYPE_MIME                                       11
#define LIST_TYPE_FILE_EXT                               12
#define LIST_TYPE_TIME                                  13
#define LIST_TYPE_MAP                                   14
#define LIST_TYPE_IPMAP                                   15
#define LIST_TYPE_ERROR                                   16
#define LIST_TYPE_TOP                                   17

#define LIST_METHOD_READF_SWS                             1
#define LIST_METHOD_READF_EWS                             2
#define LIST_METHOD_REGEXP_BOOL                       3
#define LIST_METHOD_REGEXP_REPL                        4
#define LIST_METHOD_PHRASES                                   5
#define LIST_METHOD_IP                                                  6
#define LIST_METHOD_TIME                                                7
#define LIST_METHOD_MAP                                                8
#define LIST_METHOD_IPMAP                                                9

// DECLARATIONS

class ListMeta
{
    public:
    int items;
    bool reverse_lookups = false;

    struct list_info {
        String name;
        String pwd;
        unsigned int type;
        unsigned int method_type;
        unsigned int list_ref;
        std::deque<RegExp> comp;
        std::deque<String> source;
        std::deque<String> replace;
        std::deque<unsigned int> reg_list_ref;
        unsigned int mess_no;
        unsigned int log_mess_no;
        bool anon_log;
        bool site_wild;
        bool used = false;
    };

    struct list_result {
        String match;      // to hold match from list
        String category; // holds list category
        String result;   // to hold any modified Sting
        int mess_no;
        int log_mess_no;
        bool anon_log;
    };

    std::vector<list_info> list_vec;

    String list_type(int type);

    String type_map[LIST_TYPE_TOP] = { "",
            "iplist",
            "sitelist",
            "ipsitelist",
            "urllist",
            "searchlist",
            "regexpboollist",
            "regexpreplacelist",
            "phrasebannedlist",
            "phraseweightedlist",
            "phraseexceptionlist",
            "mimelist",
            "fileextlist",
            "timelist",
            "maplist",
            "ipmaplist",
            "unknown list"
    };

    ListMeta();
    ~ListMeta();

    void reset();

    bool load_type(int type, std::deque<String> &list);

    struct list_info findList(String name, int type);
    struct list_info *findListPtr(String name, int type);

    unsigned int findListId(String name, int type);

    bool list_exists(String name, int type);

    bool inList(String name, int type, String &tofind, list_result &res);
    bool inList(list_info &list, String &tofind, list_result &res);
    bool inList(list_info &info, std::deque<String> &header,  list_result &res);



   bool readFile(const char *filename, const char *pwd, unsigned int *whichlist, bool sortsw, const char *listname,bool isip = false, bool istime = false,
           bool is_map = false);

   bool readRegExReplacementFile(const char *filename, const char *pwd, const char *listname, unsigned int &listid,
       std::deque<String> &list_rep, std::deque<RegExp> &list_comp);

private:

    char *inURLList(String &url, unsigned int list,  String &lastcategory, bool &site_wild);
    const char *inSiteList(String &url, unsigned int list,  String &lastcategory, bool &site_wild);
    const char *inSearchList(String &words, unsigned int list,String &lastcategory);
    int   inRegExpURLList(String &url, std::deque<RegExp> &list_comp, std::deque<unsigned int> &list_ref, unsigned int list, String &lastcategory);
bool regExp(String &line, std::deque<RegExp> &regexp_list, std::deque<String> &replacement_list);
    bool headerRegExpReplace(ListMeta::list_info &listi, std::deque<String> &header, list_result &res );
    int inHeaderRegExp(list_info &listi, std::deque<String> &header, list_result &res, String &lastcategory );
    bool isIPHostname(String url);
    char *testBlanketBlock(unsigned int list, bool ip, bool ssl, String &lastcategory);
    RegExp isiphost;
    bool precompileregexps();
    bool readRegExMatchFile(const char *filename, const char *pwd, const char *listname, unsigned int &listref,
        std::deque<RegExp> &list_comp, std::deque<String> &list_source, std::deque<unsigned int> &list_ref);
    bool compileRegExMatchFile(unsigned int list, std::deque<RegExp> &list_comp,
        std::deque<String> &list_source, std::deque<unsigned int> &list_ref);

};

#endif
