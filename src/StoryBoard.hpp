// StoryBoard class 

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_SB
#define __HPP_SB

// INLCUDES

#include <vector>
#include <deque>
#include <map>
#include <string>
#include "String.hpp"
#include "RegExp.hpp"
#include "SBFunction.hpp"
#include "ListMeta.hpp"


// DECLARATIONS

class StoryBoard
{
 private:

  public:
    int items;

    int fnt_cnt;
    ListMeta* LMeta;

    std::vector<SBFunction> funct_vec;

    StoryBoard();
    ~StoryBoard();

    void reset();

   bool readFile(const char *filename, ListMeta & LMeta, bool is_top = true);
   unsigned int getFunctID(String &fname);

};

#endif
