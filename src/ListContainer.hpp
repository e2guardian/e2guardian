// ListContainer class - for item and phrase lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LISTCONTAINER
#define __HPP_LISTCONTAINER

// INLCUDES

#include <vector>
#include <deque>
#include <map>
#include <list>
#include <string>
#include "String.hpp"
#include "RegExp.hpp"
#include "IPList.hpp"

// DECLARATIONS

// time limit information
struct TimeLimit {
    unsigned int sthour, stmin, endhour, endmin;
    String days, timetag;
};

#ifndef __HPP_IPLIST      // only needed if IPList.hpp is gone
// convenience structs for subnets and IP ranges
struct ipl_subnetstruct {
    uint32_t maskedaddr;
    uint32_t mask;
};

struct ipl_rangestruct {
    uint32_t startaddr;
    uint32_t endaddr;
}
#endif

// class for linking IPs to filter groups, complete with comparison operators
// allowing standard C++ sort to work
class ipmap
{
public:
    ipmap(uint32_t a, String g)
    {
        addr = a;
        group = g;
    };
    uint32_t addr;
    String group;
    int operator<(const ipmap &a) const
    {
        return addr < a.addr;
    };
    int operator<(const uint32_t &a) const
    {
        return addr < a;
    };
    int operator==(const uint32_t &a) const
    {
        return a == addr;
    };
};

class datamap
{
public:
    datamap(String &k, String &g){
        key = k;
        group = g;
    };
    String key;
    String group;
    int operator<(const datamap &a) const
    {
        return key.compare(a.key);
    };
    int operator==(const String &a) const
    {
        if( key.compare(a) == 0) return 1;
        return 0;
    };
};

// structs linking subnets and IP ranges to filter groups
struct subnetstruct {
    uint32_t maskedaddr;
    uint32_t mask;
    String group;
};

struct rangestruct {
    uint32_t startaddr;
    uint32_t endaddr;
    String group;
};

time_t getFileDate(const char *filename);
size_t getFileLength(const char *filename);

class ListContainer
{
    public:
    std::vector<int> combilist;
    bool is_iplist = false;
    bool is_timelist = false;
    bool is_map = false;
    int refcount = 0;
    bool parent = false;
    time_t filedate;
    bool used = false;
    String bannedpfile;
    String exceptionpfile;
    String weightedpfile;
    int naughtynesslimit = 0;   // used for phrase lists only
    time_t bannedpfiledate;
    time_t exceptionpfiledate;
    time_t weightedpfiledate;
    String sourcefile; // used for non-phrase lists only
    String category;
    //String lastcategory;
    std::vector<int> morelists; // has to be non private as reg exp compiler needs to access these


    ListContainer();
    ~ListContainer();

    void reset();

    bool readPhraseList(const char *filename, bool isexception, int catindex = -1, int timeindex = -1, bool incref = true, int nlimit=0);
    bool ifsreadItemList(std::istream *input, String basedir, const char *list_pwd, int len, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters);
    bool ifsReadSortItemList(std::ifstream *input, String basedir, const char *list_pwd, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters, const char *filename);
    bool readItemList(const char *filename, const char *pwd, bool startswith, int filters, bool isip = false, bool istime = false, bool ismap = false);
    bool readStdinItemList(bool startswith, int filters);
    bool inList(const char *string, String &lastcategory);
    bool inListEndsWith(const char *string, String &lastcategory);
    bool inListStartsWith(const char *string, String &lastcategory);

    const char *findInList(const char *string, String &lastcategory);

    char *findEndsWith(const char *string, String &lastcategory);
    char *findStartsWith(const char *string, String &lastcategory);
    char *findStartsWithPartial(const char *string, String &lastcategory);
    String searchIPMap(int a, int s, const uint32_t &ip);
    String inSubnetMap(const uint32_t &ip);
    String inIPRangeMap(const uint32_t &ip);

    int getListLength()
    {
        return items;
    }
    std::string getItemAtInt(int index);

    int getWeightAt(unsigned int index);
    int getTypeAt(unsigned int index);

    void doSort(const bool startsWith);

    bool createCacheFile();
    bool makeGraph(bool fqs);

    bool previousUseItem(const char *filename, bool startswith, int filters);
    bool upToDate();

    String getListCategoryAt(unsigned int index, unsigned int *catindex = NULL);
    String getListCategoryAtD(unsigned int index);

    void graphSearch(std::map<std::string, std::pair<unsigned int, int> > &result, char *doc, off_t len);


    bool isNow(int index = -1);   // used for normal and phrase lists
    bool isNowInTimelist();                 // used for timelists
    bool isNow(TimeLimit &tl);
    bool checkTimeAt(unsigned int index);
    bool checkTimeAtD(int index);

    bool blanketblock;
    bool blanket_ip_block;
    bool blanketsslblock;
    bool blanketssl_ip_block;

    private:
    bool sourceisexception = false;
    bool sourcestartswith = false;
    int sourcefilters = 0;
    char *data = nullptr;

    // Format of the data is each entry has 64 int values with format of:
    // [letter][last letter flag][num links][from phrase][link0][link1]...

    int *realgraphdata = nullptr;
    int current_graphdata_size = 0;

#ifdef E2DEBUG
    bool prolificroot = false;
    int secondmaxchildnodes = 0;
#endif

    int maxchildnodes = 0;
    int graphitems = 0;
    std::vector<unsigned int> slowgraph;
    size_t data_length = 0;
    size_t data_memory = 0;
    long int items = 0;
    bool isSW = false;
    bool issorted = false;
    bool graphused = false;
    std::vector<size_t> list;
    std::vector<size_t> lengthlist ;
    std::vector<int> weight;
    std::vector<int> itemtype; // 0=banned, 1=weighted, -1=exception
    bool force_quick_search = false;

    //time-limited lists - only items (sites, URLs), not phrases
    TimeLimit listtimelimit;
    bool istimelimited = false;

    //categorised lists - both phrases & items
    std::vector<String> listcategory;
    std::vector<int> categoryindex;

    // set of time limits for phrase lists
    std::vector<int> timelimitindex;
    std::vector<TimeLimit> timelimits;

    RegExp matchIP, matchSubnet, matchRange, matchCIDR;

    //iplists
    std::vector<uint32_t> iplist;
    std::list<ipl_rangestruct> iprangelist;
    std::list<ipl_subnetstruct> ipsubnetlist;
    std::vector<ipmap> ipmaplist;
    std::list<rangestruct> ipmaprangelist;
    std::list<subnetstruct> ipmapsubnetlist;
    //std::list<datamap> datamaplist;
    std::deque<datamap> datamaplist;

    //timelists
    std::vector<TimeLimit> timelist;

    bool readAnotherItemList(const char *filename, const char *list_pwd, bool startswith, int filters);

    void readPhraseListHelper(String line, bool isexception, int catindex, int timeindex, int &nlimit);
    void readPhraseListHelper2(String phrase, int type, int weighting, int catindex, int timeindex);
    bool addToItemListPhrase(const char *s, size_t len, int type, int weighting, bool combi, int catindex, int timeindex);
    void graphSizeSort(int l, int r, std::deque<size_t> *sizelist);
    void graphAdd(String s, const int inx, int item);
    int graphFindBranches(unsigned int pos);
    void graphCopyNodePhrases(unsigned int pos);
    int bmsearch(char *file, off_t fl, const std::string &s);
    bool readProcessedItemList(const char *filename, bool startswith, int filters);
    void addToItemList(const char *s, size_t len);
    void addToIPList(String &line);
    void addToIPMap(String &line);
    void addToDataMap(String &line);
    void addToTimeList(String &line);
    int greaterThanEWF(const char *a, const char *b); // full match
    int greaterThanEW(const char *a, const char *b); // partial ends with
    int greaterThanSWF(const char *a, const char *b); // full match
    int greaterThanSW(const char *a, const char *b); // partial starts with
    int search(int (ListContainer::*comparitor)(const char *a, const char *b), int a, int s, const char *p);
    void increaseMemoryBy(size_t bytes);
    //categorised & time-limited lists support
    bool readTimeTag(String *tag, TimeLimit &tl);
    bool readTimeBand(String &tag, TimeLimit &tl);
    int getCategoryIndex(String *lcat);
    const char *inIPList(const std::string &ipstr );
    String getIPMapData(std::string &ip);
    const char *hIPtoChar(uint32_t ip);
    String inIPMap(const uint32_t &ip);
    String getMapData(String &key);
};

#endif
