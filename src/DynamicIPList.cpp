// DynamicIPList - maintains a sorted list of IP addresses, for checking &
// limiting the number of concurrent proxy users.

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "DynamicIPList.hpp"
#include "Logger.hpp"

#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <string>
#include <cstdint>

// GLOBALS
extern thread_local std::string thread_id;

// IMPLEMENTATION

// constructor - store our options & allocate our lists
DynamicIPList::DynamicIPList(int maxitems, int maxitemage)
    : data(new unsigned long int[maxitems]), datatime(new unsigned long int[maxitems]), size(maxitems), items(0), maxage(maxitemage)
{
}

// delete the memory block when the class is destryed
DynamicIPList::~DynamicIPList()
{
    delete[] data;
    delete[] datatime;
}

// store the timestamp for the given entry, used to determine age during purge
void DynamicIPList::stamp(unsigned int pos)
{
    datatime[pos] = time(NULL);
}

// binary search for the given item
int DynamicIPList::search(int a, int s, unsigned long int ip)
{
    if (a > s)
        return (-1 - a);
    int m = (a + s) / 2;
    unsigned long int i = data[m];
    if (ip == i)
        return m;
    if (ip < i)
        return search(m + 1, s, ip);
    if (a == s)
        return (-1 - a);
    return search(a, m - 1, ip);
}

// remove entries older then maxage
void DynamicIPList::purgeOldEntries()
{
    if (items < 1)
        return;
    unsigned long int timenow = time(NULL);
    for (int i = 0; i < items; i++) {
        if ((timenow - datatime[i]) > (unsigned)maxage) {
            data[i] = 0;
        }
    }
    empties();
}

// search for given item in list
// -ve if not found 0-(pos + 1) is where it would go
// 0 to size if found
int DynamicIPList::posInList(unsigned long int ip)
{
#ifdef DEBUG_LOW
    DEBUG_debug("****** ip cache table ******");
    DEBUG_debug("items: ", items);
    int d;
    for (d = 0; d < items; d++) {
        DEBUG_debug(data[d]);
    }
    DEBUG_debug("****** ip cache table ******");
#endif
    if (items == 0) {
        return -1;
    }
    return search(0, items - 1, ip);
}

// return whether or not given IP is in/could be added to list
// (i.e. returns false if list already full & this IP's not in it)
bool DynamicIPList::inList(unsigned long int ip)
{
    // is item already in list?
    int pos = posInList(ip);
    if (pos > -1) {
        stamp(pos);
        return true;
    }

    // is list full?
    if (items >= size) {
        return false;
    }

    // list isn't full, and IP not already there, so add it
    pos = 0 - pos - 1;
    int i;
    for (i = items; i > pos; i--) {
        data[i] = data[i - 1];
        datatime[i] = datatime[i - 1];
    }
    data[pos] = ip;
    stamp(pos);
    items++;
    return true;
}

// shuffle the list to remove gaps left by a purge
void DynamicIPList::empties()
{
    int decrement = 0;
    unsigned long int t;
    int i;
    if (data[0] == 0) {
        decrement = 1;
    }
    for (i = 1; i < items; i++) {
        t = data[i];
        if (t == 0) {
            decrement++;
        } else {
            if (decrement > 0) {
                data[i - decrement] = t;
                datatime[i - decrement] = datatime[i];
            }
        }
    }
    items -= decrement;
}
