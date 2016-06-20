// ListManager - for creating & containing all ListContainers of item & phrase lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LISTMANAGER
#define __HPP_LISTMANAGER

// INCLUDES

#include "String.hpp"
#include "ListContainer.hpp"

#include <deque>

// DECLARATION

class ListManager
{
    public:
    // the lists we manage
    std::deque<ListContainer *> l;

    ~ListManager();

    void clear();

    // create a new item list. re-uses existing lists if a reload is not necessary.
    // calls readItemList.
    int newItemList(const char *filename, bool startswith, int filters, bool parent);
    int newStdinItemList(bool startswith, int filters, bool parent, const char *startstr);
    // create a new phrase list. re-uses existing lists, but cannot check nested lists (known limitation).
    // does not call readPhraseList. (checkme: why?)
    int newPhraseList(const char *exception, const char *banned, const char *weighted);

    bool readbplfile(const char *banned, const char *exception, const char *weighted, unsigned int &list, bool force_quick_search);

    void deRefList(size_t item);

    // delete lists with refcount zero
    void garbageCollect();

    private:
    // find an empty slot in our collection of listcontainters
    int findNULL();

    void refList(size_t item);
};

#endif
