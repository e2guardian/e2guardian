// ListContainer class - for item and phrase lists

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LISTCONTAINER
#define __HPP_LISTCONTAINER


// INLCUDES

#include <vector>
#include <deque>
#include <map>
#include <string>
#include "String.hpp"


// DECLARATIONS

// time limit information
struct TimeLimit {
	unsigned int sthour, stmin, endhour, endmin;
	String days, timetag;
};

time_t getFileDate(const char *filename);
size_t getFileLength(const char *filename);

class ListContainer
{
public:
	std::vector<int> combilist;
	int refcount;
	bool parent;
	time_t filedate;
	bool used;
	String bannedpfile;
	String exceptionpfile;
	String weightedpfile;
	time_t bannedpfiledate;
	time_t exceptionpfiledate;
	time_t weightedpfiledate;
	String sourcefile;  // used for non-phrase lists only
	String category;
	String lastcategory;
	std::vector<int> morelists;  // has to be non private as reg exp compiler needs to access these

	ListContainer();
	~ListContainer();

	void reset();

	bool readPhraseList(const char *filename, bool isexception, int catindex = -1, int timeindex = -1, bool incref = true);
	bool readItemList(const char *filename, bool startswith, int filters);

	bool inList(const char *string);
	bool inListEndsWith(const char *string);
	bool inListStartsWith(const char *string);

	char *findInList(const char *string);

	char *findEndsWith(const char *string);
	char *findStartsWith(const char *string);
	char *findStartsWithPartial(const char *string);


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

	String getListCategoryAt(int index, int *catindex = NULL);
	String getListCategoryAtD(int index);

	void graphSearch(std::map<std::string, std::pair<unsigned int, int> >& result, char *doc, off_t len);
	
	bool isNow(int index = -1);
	bool checkTimeAt(unsigned int index);
	bool checkTimeAtD(int index);

	bool blanketblock;
	bool blanket_ip_block;
	bool blanketsslblock;
	bool blanketssl_ip_block;

private:
	bool sourceisexception;
	bool sourcestartswith;
	int sourcefilters;
	char *data;

	// Format of the data is each entry has 64 int values with format of:
	// [letter][last letter flag][num links][from phrase][link0][link1]...

	int *realgraphdata;
	int current_graphdata_size;

#ifdef DGDEBUG
	bool prolificroot;
	int secondmaxchildnodes;
#endif

	int maxchildnodes;
	int graphitems;
	std::vector<unsigned int> slowgraph;
	size_t data_length;
	size_t data_memory;
	long int items;
	bool isSW;
	bool issorted;
	bool graphused;
	std::vector<size_t > list;
	std::vector<size_t > lengthlist;
	std::vector<int > weight;
	std::vector<int > itemtype;  // 0=banned, 1=weighted, -1=exception
	bool force_quick_search;
	
	//time-limited lists - only items (sites, URLs), not phrases
	TimeLimit listtimelimit;
	bool istimelimited;

	//categorised lists - both phrases & items
	std::vector<String> listcategory;
	std::vector<int> categoryindex;

	// set of time limits for phrase lists
	std::vector<int> timelimitindex;
	std::vector<TimeLimit> timelimits;

	bool readAnotherItemList(const char *filename, bool startswith, int filters);

	void readPhraseListHelper(String line, bool isexception, int catindex, int timeindex);
	void readPhraseListHelper2(String phrase, int type, int weighting, int catindex, int timeindex);
	bool addToItemListPhrase(const char *s, size_t len, int type, int weighting, bool combi, int catindex, int timeindex);
	void graphSizeSort(int l, int r, std::deque<size_t > *sizelist);
	void graphAdd(String s, const int inx, int item);
	int graphFindBranches(unsigned int pos);
	void graphCopyNodePhrases(unsigned int pos);
	int bmsearch(char *file, off_t fl, const std::string& s);
	bool readProcessedItemList(const char *filename, bool startswith, int filters);
	void addToItemList(const char *s, size_t len);
	int greaterThanEWF(const char *a, const char *b);  // full match
	int greaterThanEW(const char *a, const char *b);  // partial ends with
	int greaterThanSWF(const char *a, const char *b);  // full match
	int greaterThanSW(const char *a, const char *b);  // partial starts with
	int search(int (ListContainer::*comparitor)(const char* a, const char* b), int a, int s, const char *p);
	bool isCacheFileNewer(const char *string);
	void increaseMemoryBy(size_t bytes);
	//categorised & time-limited lists support
	bool readTimeTag(String * tag, TimeLimit& tl);
	int getCategoryIndex(String * lcat);
};

#endif
