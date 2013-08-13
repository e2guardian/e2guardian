// DynamicIPList - maintains a sorted list of IP addresses, for checking &
// limiting the number of concurrent proxy users.

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_DYNAMICIPLIST
#define __HPP_DYNAMICIPLIST


// DECLARATIONS

class DynamicIPList {
public:
	DynamicIPList(int maxitems, int maxitemage);
	~DynamicIPList();

#ifdef DGDEBUG
	int getListSize() { return size; };
#endif
	int getNumberOfItems() { return items; };

	// return whether or not given IP is in/could be added to list
	// (i.e. returns false if list already full & this IP's not in it)
	bool inList(unsigned long int ip);

	// remove entries older than maxage
	void purgeOldEntries();

private:
	// IPs and their ages
	unsigned long int *data;
	unsigned long int *datatime;
	
	// list size; no. of items currently in list; max. allowed item age
	int size;
	int items;
	int maxage;
	
	void stamp(unsigned int pos);
	
	// binary search for given ip
	int search(int a, int s, unsigned long int ip);
	
	// compacts list removing blanks
	void empties();
	
	// returns position of given IP in list, or (0-pos)-1 where pos is where
	// IP should be inserted to retain sorting.
	int posInList(unsigned long int ip);
};

#endif
