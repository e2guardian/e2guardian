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
#include "UrlRec.hpp"

// #include "NaughtyFilter.hpp"

//#ifndef __HPP_SB

// Entry point codes for pre-auth.story
#define  ENT_STORYA_PRE_AUTH    1
#define  ENT_STORYA_PRE_AUTH_THTTPS    2
#define  ENT_STORYA_PRE_AUTH_ICAP       3

// auth plugin entry point codes
#define  ENT_STORYA_AUTH_IP         11
#define  ENT_STORYA_AUTH_PORT         12
#define  ENT_STORYA_AUTH_BASIC_PROXY         13
#define  ENT_STORYA_AUTH_IDENT         14
#define  ENT_STORYA_AUTH_HEADER         15
#define  ENT_STORYA_AUTH_NTLM_PROXY         16
#define  ENT_STORYA_AUTH_DIGEST_PROXY         17
#define  ENT_STORYA_AUTH_ICAP   18
#define  ENT_STORYA_AUTH_PF_BASIC   19

// Entry point codes for storyfn.story
#define  ENT_STORYB_PROXY_REQUEST    1
#define  ENT_STORYB_PROXY_RESPONSE  2
#define  ENT_STORYB_THTTPS_REQUEST    3
#define  ENT_STORYB_ICAP_REQMOD 4
#define  ENT_STORYB_ICAP_RESMOD 5
#define  ENT_STORYB_LOG_CHECK 6



class NaughtyFilter;

// DECLARATIONS

class StoryBoard
{
 private:
    unsigned int entrys[20];
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

    bool runFunct(String &fname, NaughtyFilter &cm);
    bool runFunct(unsigned int fID, NaughtyFilter &cm);
    //bool runFunctEntry1(NaughtyFilter &cm);
    //bool runFunctEntry2(NaughtyFilter &cm);
    bool runFunctEntry(unsigned int index,  NaughtyFilter &cm);
    bool setEntry(unsigned int index, String fname);
    //bool setEntry1(String fname);
    //bool setEntry2(String fname);
    std::deque<url_rec> deep_urls(String & url, NaughtyFilter &cm);
    std::deque<url_rec>  ipToHostname(NaughtyFilter &cm);
    bool has_reverse_hosts(std::deque<url_rec> & urec, NaughtyFilter &cm);
};

//#endif
#define __HPP_SB
#endif
