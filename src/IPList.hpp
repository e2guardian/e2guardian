// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_IPLIST
#define __HPP_IPLIST

// INCLUDES

#include <list>
#include <cstdint>

// DECLARATIONS

// convenience structs for subnets and IP ranges
struct ipl_subnetstruct {
    uint32_t maskedaddr;
    uint32_t mask;
};

struct ipl_rangestruct {
public:
    uint32_t startaddr;
    uint32_t endaddr;
    int operator<(const ipl_rangestruct &a) const
    {
        if (startaddr < a.startaddr)
            return 1;
        return 0;
    }
};

// IP subnet/range/mask & hostname list
class IPList
{
    public:
    void reset();
    bool inList(const std::string &ipstr, std::string *&host) const;
    bool ifsreadIPMelangeList(std::ifstream *input, bool checkendstring, const char *endstring);
    bool readIPMelangeList(const char *filename);

    private:
    std::vector<uint32_t> iplist;
    std::vector<String> hostlist;
    std::vector<ipl_rangestruct> iprangelist;
    //std::list<ipl_subnetstruct> ipsubnetlist;
};

#endif
