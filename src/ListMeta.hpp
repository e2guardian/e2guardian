// ListContainer class - for item and phrase lists

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

#define LIST_METHOD_READF_SWS                             1
#define LIST_METHOD_READF_EWS                             2
#define LIST_METHOD_REGEXP_BOOL                       3
#define LIST_METHOD_REGEXP_REPL                        4
#define LIST_METHOD_PHRASES                                   5
#define LIST_METHOD_IP                                                  6

// DECLARATIONS

class ListMeta
{
    public:
    int items;

    struct list_info {
        String name;
        unsigned int type;
        unsigned int list_ref;
        std::deque<RegExp> comp;
        std::deque<String> source;
        std::deque<String> replace;
        std::deque<unsigned int> reg_list_ref;
        unsigned int mess_no;
        unsigned int log_mess_no;
    };
    std::vector<list_info> list_vec;

    ListMeta();
    ~ListMeta();

    void reset();

    bool load_type(int type, std::deque<String> list);

    struct list_info findList(String name, int type);

    bool list_exists(String name, int type);

   // bool readPhraseList(const char *filename, bool isexception, int catindex = -1, int timeindex = -1, bool incref = true);
    //bool ifsreadItemList(std::ifstream *input, int len, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters);
   // bool ifsReadSortItemList(std::ifstream *input, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters, const char *filename);
   // bool readItemList(const char *filename, bool startswith, int filters);
   bool readFile(const char *filename, unsigned int *whichlist, bool sortsw, const char *listname);

private:

};

#endif
