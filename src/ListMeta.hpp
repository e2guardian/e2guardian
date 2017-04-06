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


// DECLARATIONS

class ListMeta
{
    public:
    std::vector<int> list_info;
    int items;
    bool parent;
    String sourcefile; // used for non-phrase lists only

    struct list_info {
        String name;
        int type;
        int list_ref;
        std::deque<RegExp> comp;
        std::deque<String> source;
        std::deque<String> replace;
        std::deque<unsigned int> reg_list_ref;
        int mess_no;
        int log_mess_no;
    };

    ListMeta();
    ~ListMeta();

    void reset();

    bool readPhraseList(const char *filename, bool isexception, int catindex = -1, int timeindex = -1, bool incref = true);
    bool ifsreadItemList(std::ifstream *input, int len, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters);
    bool ifsReadSortItemList(std::ifstream *input, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters, const char *filename);
    bool readItemList(const char *filename, bool startswith, int filters);

private:

};

#endif
