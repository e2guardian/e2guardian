// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "LOptionContainer.hpp"
#include "OptionContainer.hpp"
#include "RegExp.hpp"
#include "ConfigVar.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <syslog.h>
#include <dirent.h>
#include <cstdlib>
#include <unistd.h> // checkme: remove?

// GLOBALS

extern bool is_daemonised;

extern OptionContainer o;



// IMPLEMENTATION

LOptionContainer::LOptionContainer()
    :  reporting_level(0), fg(NULL), numfg(0)
{
}

LOptionContainer::LOptionContainer(int load_id)
        :   reporting_level(0), fg(NULL), numfg(0)
{
    loaded_ok = true;
    if (!exception_ip_list.readIPMelangeList(o.exception_ip_list_location.c_str())) {
        std::cout << "Failed to read exceptioniplist" << std::endl;
        loaded_ok = false;
    }
    if (!banned_ip_list.readIPMelangeList(o.banned_ip_list_location.c_str())) {
        std::cout << "Failed to read bannediplist" << std::endl;
        loaded_ok = false;
    }

     if (o.use_filter_groups_list)  {
          if (!doReadItemList(o.filter_groups_list_location.c_str(), &filter_groups_list, "filtergroupslist", true)) {
              std::cout << "Failed to read filtergroupslist" << std::endl;
              loaded_ok = false;
          }
     }

    if(! readFilterGroupConf())  {
        loaded_ok = false;
        if (!is_daemonised)
            std::cout << "Error in reading filter group files" << std::endl;
        else
            syslog(LOG_INFO, "Error in reading filter group files");
    }
    reload_id = load_id;
    ++o.LC_cnt;
    if (load_id == 0)    o.numfg = numfg;   // do this on first load only
}


LOptionContainer::~LOptionContainer()
{
    reset();
}

void LOptionContainer::reset()
{
    deleteFilterGroups();
    deleteRooms();
    exception_ip_list.reset();
    banned_ip_list.reset();
    conffile.clear();
    if (o.use_filter_groups_list)
        filter_groups_list.reset();
    --o.LC_cnt;
}

void LOptionContainer::deleteFilterGroups()
{
    for (int i = 0; i < numfg; i++) {
        if (fg[i] != NULL) {
#ifdef DGDEBUG
            std::cout << "In deleteFilterGroups loop" << std::endl;
#endif
            delete fg[i]; // delete extra FOptionContainer objects
            fg[i] = NULL;
        }
    }
    if (numfg > 0) {
        delete[] fg;
        numfg = 0;
    }
}

void LOptionContainer::deleteFilterGroupsJustListData()
{
    for (int i = 0; i < numfg; i++) {
        if (fg[i] != NULL) {
            fg[i]->resetJustListData();
        }
    }
}


bool LOptionContainer::read(std::string& filename, int type, std::string& exception_ip_list_location,
                            std::string& banned_ip_list_location)
{
	conffilename = filename;

	// all sorts of exceptions could occur reading conf files
	try {
		std::string linebuffer;
		String temp;  // for tempory conversion and storage
		std::ifstream conffiles(filename.c_str(), std::ios::in);  // e2guardian.conf
		if (!conffiles.good()) {
			if (!is_daemonised) {
				std::cerr << "error reading: " << filename.c_str() << std::endl;
			}
			syslog(LOG_ERR, "%s", "error reading e2guardian.conf");
			return false;
		}
		while (!conffiles.eof()) {
			getline(conffiles, linebuffer);
			if (!conffiles.eof() && linebuffer.length() != 0) {
				if (linebuffer[0] != '#') {	// i.e. not commented out
					temp = (char *) linebuffer.c_str();
					if (temp.contains("#")) {
						temp = temp.before("#");
					}
					temp.removeWhiteSpace();  // get rid of spaces at end of line
					linebuffer = temp.toCharArray();
					conffile.push_back(linebuffer);  // stick option in deque
				}
			}
		}
		conffiles.close();

		if (type == 0 || type == 2) {



            if (type == 0) {
				return true;
			}
		}



        if (((per_room_directory_location = findoptionS("perroomdirectory")) != "") || ((per_room_directory_location = findoptionS("perroomblockingdirectory")) != "")) {
            loadRooms(true);
        }


//        filter_groups_list_location = findoptionS("filtergroupslist");
//        std::string banned_ip_list_location(findoptionS("bannediplist"));
//        std::string exception_ip_list_location(findoptionS("exceptioniplist"));
//        group_names_list_location = findoptionS("groupnamesfile");
//        std::string language_list_location(languagepath + "messages");

        if (!exception_ip_list.readIPMelangeList(exception_ip_list_location.c_str())) {
            std::cout << "Failed to read exceptioniplist" << std::endl;
            return false;
        }
        if (!banned_ip_list.readIPMelangeList(banned_ip_list_location.c_str())) {
            std::cout << "Failed to read bannediplist" << std::endl;
            return false;
        }

        if (!readFilterGroupConf()) {
            if (!is_daemonised) {
                std::cerr << "Error reading filter group conf file(s)." << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error reading filter group conf file(s).");
            return false;
        }

    } catch (std::exception &e) {
        if (!is_daemonised) {
            std::cerr << e.what() << std::endl; // when called the daemon has not
            // detached so we can do this
        }
        return false;
    }
    return true;
}


char *LOptionContainer::inSiteList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    String lastcategory;
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        url = url.before("/"); // chop off any path after the domain
    }
    char *i;
    //bool isipurl = isIPHostname(url);
    while (url.contains(".")) {
        i = lc->findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
        url = url.after("."); // check for being in higher level domains
    }
    if (url.length() > 1) { // allows matching of .tld
        url = "." + url;
        i = lc->findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
    }
    return NULL; // and our survey said "UUHH UURRGHH"
}

// look in given URL list for given URL
char *LOptionContainer::inURLList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    unsigned int fl;
    char *i;
    String lastcategory;
    String foundurl;
#ifdef DGDEBUG
    std::cout << "inURLList: " << url << std::endl;
#endif
    //syslog(LOG_ERR, "inURLList url %s", url.c_str());
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        String tpath("/");
        tpath += url.after("/");
        url = url.before("/");
        tpath.hexDecode();
        tpath.realPath();
        url += tpath; // will resolve ../ and %2e2e/ and // etc
    }
    if (url.endsWith("/")) {
        url.chop(); // chop off trailing / if any
    }
#ifdef DGDEBUG
    std::cout << "inURLList (processed): " << url << std::endl;
#endif
    //  syslog(LOG_ERR, "inURLList (processed) url %s", url.c_str());
    while (url.before("/").contains(".")) {
        i = lc->findStartsWith(url.toCharArray(), lastcategory);
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
#ifdef DGDEBUG
            std::cout << "foundurl: " << foundurl << foundurl.length() << std::endl;
            std::cout << "url: " << url << fl << std::endl;
#endif
            //syslog(LOG_ERR, "inURLList foundurl  %s", foundurl.c_str());
            if (url.length() > fl) {
                if (url[fl] == '/' || url[fl] == '?' || url[fl] == '&' || url[fl] == '=') {
                    return i; // matches /blah/ or /blah/foo but not /blahfoo
                }
            } else {
                return i; // exact match
            }
        }
        url = url.after("."); // check for being in higher level domains
    }
    return NULL;
}


bool LOptionContainer::doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort)
{
    bool result = lc->readItemList(filename, false, 0);
    if (!result) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << fname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", fname);
        return false;
    }
    if (swsort)
        lc->doSort(true);
    else
        lc->doSort(false);
    return true;
}

bool LOptionContainer::inExceptionIPList(const std::string *ip, std::string *&host)
{
    return exception_ip_list.inList(*ip, host);
}

bool LOptionContainer::inBannedIPList(const std::string *ip, std::string *&host)
{
    return banned_ip_list.inList(*ip, host);
}

// TODO: Filter rules should migrate to FOptionContainer.cpp ?  -- No, these are not filtergroup rules but nmaybe to their own cpp??

bool LOptionContainer::inRoom(const std::string &ip, std::string &room, std::string *&host, bool *block, bool *part_block, bool *isexception, String url)
{
    String temp;
    char *ret;
    for (std::list<struct room_item>::const_iterator i = rooms.begin(); i != rooms.end(); ++i) {
        if (i->iplist->inList(ip, host)) {
#ifdef DGDEBUG
            std::cerr << " IP is in room: " << i->name << std::endl;
#endif
            temp = url;
            ListContainer *lc;
            if (i->sitelist) {
                lc = i->sitelist;
                if (inSiteList(temp, lc, false, false)) {
#ifdef DGDEBUG
                    std::cerr << " room site exception found: " << std::endl;
#endif
                    *isexception = true;
                    room = i->name;
                    return true;
                }
            }
            temp = url;
            if (i->urllist && inURLList(temp, i->urllist, false, false)) {
#ifdef DGDEBUG
                std::cerr << " room url exception found: " << std::endl;
#endif
                *isexception = true;
                room = i->name;
                return true;
            }
            if (i->block) {
                *block = true;
                *part_block = i->part_block;
                room = i->name;
#ifdef DGDEBUG
                std::cerr << " room blanket block active: " << std::endl;
#endif
                return true;
            } else {
#ifdef DGDEBUG
                std::cerr << " room - no url/site exception or block found: " << std::endl;
#endif
                return false;
            }
        }
    }
    return false;
}

// TODO: Filter rules should migrate to FOptionContainer.cpp ?

void LOptionContainer::loadRooms(bool throw_error)
{
    if (!throw_error && (per_room_directory_location == ""))
        return;
    DIR *d = opendir(per_room_directory_location.c_str());
    if (d == NULL) {
        if (throw_error) {
            syslog(LOG_ERR, "Could not open room definitions directory: %s", strerror(errno));
            std::cerr << "Could not open room definitions directory" << std::endl;
            exit(1);
        } else {
            return;
        }
    }

    struct dirent *f;
    while ((f = readdir(d))) {
        if (f->d_name[0] == '.')
            continue;
        std::string filename(per_room_directory_location);
        filename.append(f->d_name);
#ifdef DGDEBUG
        std::cerr << " Room file found : " << filename.c_str() << std::endl;
#endif
        std::ifstream infile(filename.c_str(), std::ios::in);
        if (!infile.good()) {
            syslog(LOG_ERR, " Could not open file room definitions ");
            std::cerr << " Could not open file room definitions: " << filename.c_str() << std::endl;
            exit(1);
        }
#ifdef DGDEBUG
        std::cerr << " Opened room file : " << filename.c_str() << std::endl;
#endif

        std::string roomname;
#ifdef DGDEBUG
        std::cerr << " Reading room file : " << filename.c_str() << std::endl;
#endif
        getline(infile, roomname);
        if (infile.eof()) {
            syslog(LOG_ERR, " Unexpected EOF ");
            std::cerr << " Unexpected EOF: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (infile.fail()) {
            syslog(LOG_ERR, " Unexpected failue on read");
            std::cerr << " Unexpected failure on read: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (infile.bad()) {
            syslog(LOG_ERR, " Unexpected badbit failue on read");
            std::cerr << " Unexpected badbit failure on read: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (!infile.good()) {
            syslog(LOG_ERR, " Could not open file room definitions ");
            std::cerr << " Could not open file room definitions: " << filename.c_str() << std::endl;
            exit(1);
        }
#ifdef DGDEBUG
        std::cerr << " Room name is: " << roomname.c_str() << std::endl;
#endif
        roomname = roomname.substr(1);
        room_item this_room;
        this_room.name = roomname;
        this_room.block = false;
        this_room.part_block = false;
        this_room.sitelist = NULL;
        this_room.urllist = NULL;

        IPList *contents = new IPList();
        contents->ifsreadIPMelangeList(&infile, true, "#ENDLIST");
        this_room.iplist = contents;
        if (infile.eof()) { // is old style room block
            this_room.block = true;
            this_room.sitelist = NULL;
            this_room.urllist = NULL;
        } else {
            std::string linestr;
            String temp;
            while (infile.good()) {
                std::getline(infile, linestr);
                if (infile.eof())
                    break;
                temp = linestr;
                if (temp.startsWith("#SITELIST")) {
                    ListContainer *sitelist = new ListContainer();
                    if (sitelist->ifsReadSortItemList(&infile, true, "#ENDLIST", false, false, 0, filename.c_str())) {
                        this_room.sitelist = sitelist;
                    } else {
                        delete sitelist;
                    }
                } else if (temp.startsWith("#URLLIST")) {
                    ListContainer *urllist = new ListContainer();
                    if (urllist->ifsReadSortItemList(&infile, true, "#ENDLIST", false, true, 0, filename.c_str())) {
                        this_room.urllist = urllist;
                    } else {
                        delete urllist;
                    }
                } else if (temp.startsWith("#BLOCK")) {
                    this_room.block = true;
                }
            }
        }
        if (this_room.block && (this_room.sitelist || this_room.urllist))
            this_room.part_block = true;
        rooms.push_back(this_room);
        infile.close();
        if (roomname.size() <= 2) {
            if (!is_daemonised) {
                std::cerr << "Could not read room from definitions file \"" << filename << '"' << std::endl;
            }
            syslog(LOG_ERR, "Could not read room from definitions file \"%s\"",
                filename.c_str());
            exit(1);
        }
        roomname = roomname.substr(1); // remove leading '#'
    }

    if (closedir(d) != 0) {
        if (errno != EINTR) {
            syslog(LOG_ERR, "Could not close room definitions directory: %s", strerror(errno));
            exit(1);
        }
    }
}

void LOptionContainer::deleteRooms()
{
    for (std::list<room_item>::iterator i = rooms.begin(); i != rooms.end(); ++i) {
        delete i->iplist;
        if (i->sitelist != NULL)
            delete i->sitelist;
        if (i->urllist != NULL)
            delete i->urllist;
    }
    rooms.clear();
}

long int LOptionContainer::findoptionI(const char *option)
{
    long int res = String(findoptionS(option).c_str()).toLong();
    return res;
}

std::string LOptionContainer::findoptionS(const char *option)
{
    // findoptionS returns a found option stored in the deque
    String temp;
    String temp2;
    String o(option);

    for (std::deque<std::string>::iterator i = conffile.begin(); i != conffile.end(); i++) {
        if ((*i).empty())
            continue;
        temp = (*i).c_str();
        temp2 = temp.before("=");
        while (temp2.endsWith(" ")) { // get rid of tailing spaces before =
            temp2.chop();
        }
        if (o == temp2) {
            temp = temp.after("=");
            while (temp.startsWith(" ")) { // get rid of heading spaces
                temp.lop();
            }
            if (temp.startsWith("'")) { // inverted commas
                temp.lop();
            }
            while (temp.endsWith(" ")) { // get rid of tailing spaces
                temp.chop();
            }
            if (temp.endsWith("'")) { // inverted commas
                temp.chop();
            }
            return temp.toCharArray();
        }
    }
    return "";
}

std::deque<String> LOptionContainer::findoptionM(const char *option)
{
    // findoptionS returns all the matching options
    String temp;
    String temp2;
    String o(option);
    std::deque<String> results;

    for (std::deque<std::string>::iterator i = conffile.begin(); i != conffile.end(); i++) {
        if ((*i).empty())
            continue;
        temp = (*i).c_str();
        temp2 = temp.before("=");
        while (temp2.endsWith(" ")) { // get rid of tailing spaces before =
            temp2.chop();
        }
        if (o == temp2) {
            temp = temp.after("=");
            while (temp.startsWith(" ")) { // get rid of heading spaces
                temp.lop();
            }
            if (temp.startsWith("'")) { // inverted commas
                temp.lop();
            }
            while (temp.endsWith(" ")) { // get rid of tailing spaces
                temp.chop();
            }
            if (temp.endsWith("'")) { // inverted commas
                temp.chop();
            }
            results.push_back(temp);
        }
    }
    return results;
}

bool LOptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage)
{
    // realitycheck checks an amount for certain expected criteria
    // so we can spot problems in the conf files easier
    if ((l < minl) || ((maxl > 0) && (l > maxl))) {
        if (!is_daemonised) {
            // when called we have not detached from
            // the console so we can write back an
            // error

            std::cerr << "Config problem; check allowed values for " << emessage << std::endl;
        }
        syslog(LOG_ERR, "Config problem; check allowed values for %s", emessage);
        return false;
    }
    return true;
}

bool LOptionContainer::readFilterGroupConf()
{
    String prefix(o.conffilename);
    prefix = prefix.before(".conf");
    prefix += "f";
    String file;
    ConfigVar groupnamesfile;
    String groupname;
    bool need_html = false;
    if (o.use_group_names_list) {
        int result = groupnamesfile.readVar(group_names_list_location.c_str(), "=");
        if (result != 0) {
            if (!is_daemonised)
                std::cerr << "Error opening group names file: " << group_names_list_location << std::endl;
            syslog(LOG_ERR, "Error opening group names file: %s", group_names_list_location.c_str());
            return false;
        }
    }
    for (int i = 1; i <= o.filter_groups; i++) {
        file = prefix + String(i);
        file += ".conf";
        if (o.use_group_names_list) {
            std::ostringstream groupnum;
            groupnum << i;
            groupname = groupnamesfile[groupnum.str().c_str()];
            if (groupname.length() == 0) {
                if (!is_daemonised)
                    std::cerr << "Group names file too short: " << group_names_list_location << std::endl;
                syslog(LOG_ERR, "Group names file too short: %s", group_names_list_location.c_str());
                return false;
            }
#ifdef DGDEBUG
            std::cout << "Group name: " << groupname << std::endl;
#endif
        }
        if (!readAnotherFilterGroupConf(file.toCharArray(), groupname.toCharArray(), need_html)) {
            if (!is_daemonised) {
                std::cerr << "Error opening filter group config: " << file << std::endl;
            }
            syslog(LOG_ERR, "Error opening filter group config: %s", file.toCharArray());
            return false;
        }
    }
    return true;
}

bool LOptionContainer::readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html)
{
#ifdef DGDEBUG
    std::cout << "adding filter group: " << numfg << " " << filename << std::endl;
#endif

    // array of pointers to FOptionContainer
    typedef FOptionContainer *PFOptionContainer;
    FOptionContainer **temp = new PFOptionContainer[numfg + 1];
    for (int i = 0; i < numfg; i++) {
        temp[i] = fg[i];
    }
    if (numfg > 0) {
        delete[] fg;
    }
    fg = temp;
    fg[numfg] = new FOptionContainer;

#ifdef DGDEBUG
    std::cout << "added filter group: " << numfg << " " << filename << std::endl;
#endif

    // pass all the vars from OptionContainer needed
    (*fg[numfg]).weighted_phrase_mode = o.weighted_phrase_mode;
    (*fg[numfg]).force_quick_search = o.force_quick_search;
    (*fg[numfg]).reverse_lookups = o.reverse_lookups;

    // pass in the group name
    (*fg[numfg]).name = groupname;

    // pass in the reporting level - can be overridden
    (*fg[numfg]).reporting_level = reporting_level;

#ifdef DGDEBUG
    std::cout << "passed variables to filter group: " << numfg << " " << filename << std::endl;
#endif

    bool rc = (*fg[numfg]).read(filename);
#ifdef DGDEBUG
    std::cout << "read filter group: " << numfg << " " << filename << std::endl;
#endif

    numfg++;

    if (!rc) {
        return false;
    }
    return true;
}
