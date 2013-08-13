// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_DYNAMICURLLIST
#define __HPP_DYNAMICURLLIST

// dynamic URL lists - used to cache known clean URLs so filtering can be bypassed
class DynamicURLList
{
public:
	DynamicURLList();
	~DynamicURLList();

	// set list size and timeout on entries (old entries aren't deleted, simply overwritten)
	bool setListSize(unsigned int s, unsigned int t);
	// flush the list (set all entries to old)
	void flush();
	// is an entry in the list?
	bool inURLList(const char *url, const int fg);
	// add a URL - if it's already there but marked as too old, simply rejuvenate it
	void addEntry(const char *url, const int fg);

private:
	// index list - points to URL list entries in alphabetical order
	unsigned int *index;
	// age list, sorted in the same order as index
	unsigned long int *urlreftime;
	// actual URL list
	char *urls;
	// group list - which group(s) is this URL clean for?
	std::string *groups;

	// size of list
	int size;
	// pointer to oldest entry (real entry, not sorted index)
	int agepos;
	unsigned int timeout;
	int items;
	
	// binary search for the pos of the given url in the sorted index
	// returns 0-(pos+1) on failure, where pos is where the entry would be inserted to retain sorting
	int search(int a, int s, const char *url);
	// find the index for the given url - makes use of the above search func
	int posInList(const char *url);
};

#endif
