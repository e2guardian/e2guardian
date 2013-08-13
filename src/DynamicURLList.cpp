// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "OptionContainer.hpp"
#include "DynamicURLList.hpp"

#include <string.h>
#include <syslog.h>
#include <algorithm>
#include <ctime>
#include <sys/stat.h>
#include <sys/time.h>


// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;


// IMPLEMENTATION

// note - the list of URLs itself is simply a ring buffer, so the oldest entry/next empty entry is always the
// last position we wrote to plus one, wrapping round when we get to the top.
// however, we also maintain a seperate index list, which points to the entries in alphabetical order.

// constructor - initialise values to empty defaults
DynamicURLList::DynamicURLList()
:index(NULL), urlreftime(NULL), urls(NULL), groups(NULL), size(0), agepos(0), timeout(0), items(0)
{
}

// delete the memory block when the class is destryed
DynamicURLList::~DynamicURLList()
{
	delete[]index;
	delete[]urlreftime;
	delete[]urls;
	delete[]groups;
}

// "flush" the list (not quite)
void DynamicURLList::flush()
{
	// make all entries old so they won't be used
	for (int i = 0; i < items; i++) {
		urlreftime[index[i]] = 0;
	}
}

// find the position of the given URL in the list
// return value ranges:
// -ve if not found. 0-(pos + 1) is where it should be inserted to retain sorting.
// 0 to size if found
int DynamicURLList::posInList(const char *url)
{
	if (items == 0) {
#ifdef DGDEBUG
		std::cout << "url list cache is empty" << std::endl;
#endif
		// if the list is empty, indicate that the entry should go in pos 0
		return -1;
	}
#ifdef DGDEBUG
		std::cout << "url list cache: performing search..." << std::endl;
#endif
	return search(0, items - 1, url);
}

// binary search the list for a given URL
// note the list itself is not ordered, but the index array is
int DynamicURLList::search(int a, int s, const char *url)
{
	if (a > s)
		return (-1 - a);
	int m = (a + s) / 2;
	// look up the url pointed to by this entry in the index
	char *i = index[m] * 1000 + urls;

/*#ifdef DGDEBUG
	std::cout << "url list cache: comparing " << i << " to " << url << std::endl;
#endif*/

	int alen = strlen(i);
	int blen = strlen(url);
	int maxlen = alen < blen ? alen : blen;
	char *apos = (char *) i;
	char *bpos = (char *) url;
	int j = 0;
	int c = 0;
	unsigned char achar;
	unsigned char bchar;
	while (j < maxlen) {
		achar = apos[0];
		bchar = bpos[0];
		if (achar > bchar) {
			c = 1;
			break;
		}
		if (achar < bchar) {
			c = -1;
			break;
		}
		j++;
		apos++;
		bpos++;
	}
	if (c == 0) {
		if (alen > blen) {
			c = 1;
		}
		else if (alen < blen) {
			c = -1;
		}
	}
	// otherwise, assume both equal

	// we found the entry
	if (c == 0)
		return m;
	// we didn't, but it's in the lower half
	if (c == -1)
		return search(m + 1, s, url);
	// we got the search window down to 1 entry
	if (a == s)
		// therefore, we know where the entry we were looking for
		// should be added if we are to maintain a sorted list.
		// return its position, -ve (and strictly below 0), so as to
		// provide useful information and not mess up return value checks.
		return (-1 - a);
	// we didn't find it, but it's in the upper half
	return search(a, m - 1, url);
}

// sets how many URLs the list should store, and the maximum age of an entry before it goes inactive
bool DynamicURLList::setListSize(unsigned int s, unsigned int t)
{
	if (s < 2) {
		return false;
	}
	if (t < 2) {
		return false;
	}
	size = s;
	timeout = t;
	agepos = 0;
	items = 0;
	delete[]index;
	delete[]urlreftime;
	delete[]urls;
	delete[]groups;

	index = new unsigned int[size];
	urlreftime = new unsigned long int[size];
	urls = new char[size * 1000];  // allows url up to 999 in length
	groups = new std::string[size];
	return true;
}

// see if the given URL is in the list
bool DynamicURLList::inURLList(const char *url, const int fg)
{
#ifdef DGDEBUG
	std::cout << "url cache search request: " << fg << " " << url << std::endl;
#endif
	if (items == 0) {
		return false;
	}
#ifdef DGDEBUG
	std::cout << "****** url cache table ******" << std::endl;
	std::cout << "items: " << items << std::endl;
	for (int i = 0; i < items; i++) {
		for (unsigned int j = 0; j < groups[index[i]].length(); j++) {
			std::cout << (unsigned int) (groups[index[i]][j]) << " ";
		}
		std::cout << (char*) (index[i] * 1000 + urls) << std::endl;
	}
	std::cout << "****** url cache table ******" << std::endl;
#endif

	// truncate URL if necessary, as we have a length limit on our buffers
	int pos;
	if (strlen(url) > 999) {
		String r(String(url, 999));
		pos = posInList(r.toCharArray());
	} else {
		pos = posInList(url);
	}

#ifdef DGDEBUG
	std::cout << "pos: " << pos << std::endl;
#endif

	// if we have found an entry, also check to see that it hasn't gone inactive.
	// todo: could we speed things up a little by simply refreshing the timer on the
	// old entry here, instead of having addEntry look for possible duplicates?
	// actually, i dunno. are URLs from time-limited lists cached? this might cause them to
	// continue being seen as good/bad (depending on the nature of the list) outside the
	// allotted window if they get put in the cache during it.
	if (pos > -1) {
		unsigned long int timenow = time(NULL);
		if ((timenow - urlreftime[index[pos]]) > timeout) {
#ifdef DGDEBUG
			std::cout << "found but url ttl exceeded: " << (timenow - urlreftime[index[pos]]) << std::endl;
#endif
			return false;
		}
		// o.filter_groups + 1 is a special case, meaning clean for all groups
		std::string lookfor;
		lookfor += (char)fg;
		lookfor += (char)o.filter_groups + 1;
		if (groups[index[pos]].find_first_of(lookfor) == std::string::npos) {
#ifdef DGDEBUG
			std::cout << "found but url not flagged clean for this group: " << fg << " (is clean for: ";
			for (unsigned int j = 0; j < groups[index[pos]].length(); j++) {
				std::cout << (unsigned int) (groups[index[pos]][j]) << " ";
			}
			std::cout << ")" << std::endl;
#endif
			return false;
		}
		return true;
	}
	return false;
}

// add an entry to the URL list - if it's already there, but timed out due to age, simply refresh the timer
// also, maintain the lists' sorting, to allow binary search to be performed
void DynamicURLList::addEntry(const char *url, const int fg)
{
#ifdef DGDEBUG
	std::cout << "url cache add request: " << fg << " " << url << std::endl;
	std::cout << "itemsbeforeadd: " << items << std::endl;
#endif
	int len = strlen(url);
	bool resized = false;
	char *u;
	// truncate the URL if it's too long
	if (len > 999) {
		u = new char[1000];
		u[999] = '\0';
		// bugfix - previously, truncation did the above termination, but no string copy!
		// this might never have been noticed due to high buffer size & correct termination preventing the bug causing a crash.
		memcpy(u, url, 999);
		resized = true;
		len = 999;
	} else {
		u = (char *) url;
	}
	int pos = posInList(u);
	if (pos >= 0) {		// found
		if (resized) {
			delete[]u;
		}
#ifdef DGDEBUG
		std::cout << "Entry found at pos: " << pos << std::endl;
#endif
		urlreftime[index[pos]] = time(NULL);  // reset refresh counter
		if (groups[index[pos]].find((char)fg, 0) == std::string::npos)
			groups[index[pos]] += (char)fg;  // flag it as clean for this filter group
		return;  // not going to add entry thats there already
	}

	pos = 0 - pos - 1;  // now contains the insertion point

#ifdef DGDEBUG
	std::cout << "insertion pos: " << pos << std::endl;
	std::cout << "size: " << size << std::endl;
#endif

	// the list isn't full, so simply push new entry onto the back
	if (items < size) {
#ifdef DGDEBUG
		std::cout << "items<size: " << items << "<" << size << std::endl;
#endif
		char *urlref;
		urlref = items * 1000 + urls;
		memcpy(urlref, u, len);
		urlref[len] = '\0';
		urlreftime[items] = time(NULL);
		int i;
		// shift alphabetical index list below the insertion point down by one,
		// and insert our new item.
		for (i = items; i > pos; i--) {
			index[i] = index[i - 1];
		}
		index[pos] = items;
		groups[items] = (char)fg;
		items++;
		if (resized) {
			delete[]u;
		}
		return;
	}

	// list is full, so we can't simply push a new entry on to it.
	// now replace the oldest entry but first need to find it in
	// the index to remove from there. old entries don't get deleted, just overwritten!

	// we know the pos in the list of the oldest URL, but not where it is in our sorted index list
	char *oldestref = urls + agepos * 1000;

	// now contains pos in sorted index of what we're going to overwrite
	int delpos = posInList(oldestref);  

	// do the actual overwriting, including termination and setting birthdate to now
	memcpy(oldestref, u, len);
	oldestref[len] = '\0';
	urlreftime[agepos] = time(NULL);
	groups[agepos] = (char)fg;

	// now shuffle the index list to remain sorted
	// remember: pos contains the alphabetical position of what we just added,
	// delpos contains the alphabetical position of the previous oldest entry,
	// and agepos contains the actual position in the string list of the entry we just wrote
	if (delpos == pos) {
		// the alphabetical pos of what we just deleted and what we just wrote are one and the same
		// so simply update the one index value to contain a ref to the new entry
		index[pos] = agepos;
	}
	else if (delpos < pos) {
		// the alphabetical pos of what we deleted was less than what we just wrote
		// so shift the list entries between the two up by one (losing delpos), and insert our entry
		int endpos = pos - 1;
		for (int i = delpos; i < endpos; i++) {
			index[i] = index[i + 1];
		}
		index[pos - 1] = agepos;
	}
	else if (delpos > pos) {
		// the alphabetical pos of what we just deleted was greater than what we just added,
		// so starting from the old pos, work backwards, shifting the entries down by one
		// then insert our new entry
		for (int i = delpos; i > pos; i--) {
			index[i] = index[i - 1];
		}
		index[pos] = agepos;
	}
	// the index is now sorted, but the actual list of strings itself is sorted oldest first.
	// increase the age pointer to the next empty entry - once we get to the end, wrap round
	// to the top, and overwrite the entries oldest first.
	
	// todo: things might speed up if we simply maintain the agepos as an index into the sorted index array,
	// rather than an index on the real URL list. then we wouldn't need to do a posInList to find the agepos's
	// sorted index every time we do an add.
	agepos++;
	if (agepos == size) {
		agepos = 0;
	}

	if (resized) {
		delete[]u;
	}
}
