// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "LOptionContainer.hpp"
#include "OptionContainer.hpp"
#include "RegExp.hpp"
#include "ConfigVar.hpp"

#include <cstdio>
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
extern thread_local std::string thread_id;



// IMPLEMENTATION

LOptionContainer::LOptionContainer()
{
}

LOptionContainer::LOptionContainer(int load_id)
{
    char buff[40];

    sprintf(buff, "%ld", time(NULL));
    start_time = buff;

    loaded_ok = true;

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "iplist deque is size " << o.iplist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_IP, o.iplist_dq))
            loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "sitelist deque is size " << o.sitelist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_SITE, o.sitelist_dq))
        loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "ipsitelist deque is size " << o.ipsitelist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_IPSITE, o.ipsitelist_dq))
        loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "urllist deque is size " << o.urllist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_URL, o.urllist_dq))
        loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "regexpboollist deque is size " << o.regexpboollist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_REGEXP_BOOL, o.regexpboollist_dq))
            loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "maplist deque is size " << o.maplist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_MAP, o.maplist_dq))
            loaded_ok = false;
    }

    {
#ifdef E2DEBUG
        std::cerr << thread_id << "ipmaplist deque is size " << o.ipmaplist_dq.size() << std::endl;
#endif
        if(!LMeta.load_type(LIST_TYPE_IPMAP, o.ipmaplist_dq))
            loaded_ok = false;
    }

    if (!StoryA.readFile(o.storyboard_location.c_str(), LMeta, true)) {
        std::cerr << thread_id << "Storyboard not loaded OK" << std::endl;
        loaded_ok = false;
    }

    if (loaded_ok && !StoryA.setEntry(ENT_STORYA_PRE_AUTH,"pre-authcheck")) {
        std::cerr << thread_id << "Required storyboard entry function 'pre-authcheck' is missing" << std::endl;
        loaded_ok = false;
    }

    if (loaded_ok && (o.transparenthttps_port > 0) && !StoryA.setEntry(ENT_STORYA_PRE_AUTH_THTTPS,"thttps-pre-authcheck")) {
        std::cerr << thread_id << "Required storyboard entry function 'thttps-pre-authcheck' is missing" << std::endl;
        loaded_ok = false;
    }

    if (loaded_ok && (o.icap_port > 0) && !StoryA.setEntry(ENT_STORYA_PRE_AUTH_ICAP,"icap-pre-authcheck")) {
        std::cerr << thread_id << "Required storyboard entry function 'icap-pre-authcheck' is missing" << std::endl;
        loaded_ok = false;
    }

 //   if (loaded_ok && o.use_filter_groups_list)  {
 //       if (!doReadItemList(o.filter_groups_list_location.c_str(), &filter_groups_list, "filtergroupslist", true)) {
 //           std::cerr << thread_id << "Failed to read filtergroupslist" << std::endl;
 //           loaded_ok = false;
 //       }
 //   }

    if (loaded_ok && o.auth_entry_dq.size() > 0)  {
            for (std::deque<struct OptionContainer::auth_entry>::const_iterator i = o.auth_entry_dq.begin(); i != o.auth_entry_dq.end(); ++i) {
                if (!StoryA.setEntry(i->entry_id, i->entry_function)) {
                    std::cerr << thread_id << "Required auth storyboard entry function" << i->entry_function.c_str()
                              << " is missing from pre_auth.stoary" << std::endl;
                    loaded_ok = false;
                }
            }
    }


    if(loaded_ok && (!readFilterGroupConf() || (o.abort_on_missing_list && o.config_error)))  {
        loaded_ok = false;
        if (!is_daemonised)
            std::cerr << thread_id << "Error in reading filter group files" << std::endl;
        else
            syslog(LOG_INFO, "Error in reading filter group files");
    }
    reload_id = load_id;
    ++o.LC_cnt;
    if (load_id == 0)    o.numfg = numfg;   // do this on first load only
}


const char *LOptionContainer::inSiteList(String &url, ListContainer *lc, bool ip, bool ssl)
{
    String lastcategory;
    url.removeWhiteSpace(); // just in case of weird browser crap
    url.toLower();
    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        url = url.before("/"); // chop off any path after the domain
    }
    const char *i;
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
#ifdef E2DEBUG
    std::cerr << thread_id << "inURLList: " << url << std::endl;
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
#ifdef E2DEBUG
    std::cerr << thread_id << "inURLList (processed): " << url << std::endl;
#endif
    //  syslog(LOG_ERR, "inURLList (processed) url %s", url.c_str());
    while (url.before("/").contains(".")) {
        i = lc->findStartsWith(url.toCharArray(), lastcategory);
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
#ifdef E2DEBUG
            std::cerr << thread_id << "foundurl: " << foundurl << foundurl.length() << std::endl;
            std::cerr << thread_id << "url: " << url << fl << std::endl;
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

#ifdef NOTDEF
bool LOptionContainer::doReadItemList(const char *filename, ListContainer *lc, const char *fname, bool swsort)
{
    bool result = lc->readItemList(filename, false, 0);
    if (!result) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error opening " << fname << std::endl;
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
#endif

bool LOptionContainer::inExceptionIPList(const std::string *ip, std::string *&host)
{
    return exception_ip_list.inList(*ip, host);
}

// TODO: Filter rules should migrate to FOptionContainer.cpp ?  -- No, these are not filtergroup rules but nmaybe to their own cpp??

bool LOptionContainer::inRoom(const std::string &ip, std::string &room, std::string *host, bool *block, bool *part_block, bool *isexception, String url)
{
    String temp;
    for (std::list<struct room_item>::const_iterator i = rooms.begin(); i != rooms.end(); ++i) {
        if (i->iplist->inList(ip, host)) {
#ifdef E2DEBUG
            std::cerr << thread_id << " IP is in room: " << i->name << std::endl;
#endif
            temp = url;
            ListContainer *lc;
            if (i->sitelist) {
                lc = i->sitelist;
                if (inSiteList(temp, lc, false, false)) {
#ifdef E2DEBUG
                    std::cerr << thread_id << " room site exception found: " << std::endl;
#endif
                    *isexception = true;
                    room = i->name;
                    return true;
                }
            }
            temp = url;
            if (i->urllist && inURLList(temp, i->urllist, false, false)) {
#ifdef E2DEBUG
                std::cerr << thread_id << " room url exception found: " << std::endl;
#endif
                *isexception = true;
                room = i->name;
                return true;
            }
            if (i->block) {
                *block = true;
                *part_block = i->part_block;
                room = i->name;
#ifdef E2DEBUG
                std::cerr << thread_id << " room blanket block active: " << std::endl;
#endif
                return true;
            } else {
#ifdef E2DEBUG
                std::cerr << thread_id << " room - no url/site exception or block found: " << std::endl;
#endif
                return false;
            }
        }
    }
    return false;
}



LOptionContainer::~LOptionContainer()
{
    reset();
}

void LOptionContainer::reset()
{
    deleteFilterGroups();
    deleteRooms();
    conffile.clear();
    --o.LC_cnt;
}

void LOptionContainer::deleteFilterGroups()
{
    for (int i = 0; i < numfg; i++) {
        if (fg[i] != NULL) {
#ifdef E2DEBUG
            std::cerr << thread_id << "In deleteFilterGroups loop" << std::endl;
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

#ifdef NOTDEF
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
				std::cerr << thread_id << "error reading: " << filename.c_str() << std::endl;
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
        {
            std::deque<String> dq = findoptionM("iplist");
            std::cerr << thread_id << "iplist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_IP, dq);
        }

        {
            std::deque<String> dq = findoptionM("sitelist");
            std::cerr << thread_id << "sitelist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_SITE, dq);
        }

        {
            std::deque<String> dq = findoptionM("ipsitelist");
            std::cerr << thread_id << "ipsitelist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_IPSITE, dq);
        }

        {
            std::deque<String> dq = findoptionM("urllist");
            std::cerr << thread_id << "urllist deque is size " << dq.size() << std::endl;
            LMeta.load_type(LIST_TYPE_URL, dq);
        }

        if (!StoryA.readFile(o.storyboard_location.c_str(), LMeta, true))
            return false;

        if (!StoryA.setEntry1("pre-authcheck")) {
            std::cerr << thread_id << "Required storyboard entry function 'pre-authcheck' is missing" << std::endl;
            return false;
        }

        if (!readFilterGroupConf()) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error reading filter group conf file(s)." << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error reading filter group conf file(s).");
            return false;
        }

    } catch (std::exception &e) {
        if (!is_daemonised) {
            std::cerr << thread_id << e.what() << std::endl; // when called the daemon has not
            // detached so we can do this
        }
        return false;
    }
    return true;
}
#endif





// TODO: Filter rules should migrate to FOptionContainer.cpp ?  -- No, these are not filtergroup rules but nmaybe to their own cpp??



void LOptionContainer::loadRooms(bool throw_error)
{
    if (!throw_error && (per_room_directory_location == ""))
        return;
    DIR *d = opendir(per_room_directory_location.c_str());
    if (d == NULL) {
        if (throw_error) {
            syslog(LOG_ERR, "Could not open room definitions directory: %s", strerror(errno));
            std::cerr << thread_id << "Could not open room definitions directory" << std::endl;
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
#ifdef E2DEBUG
        std::cerr << thread_id << " Room file found : " << filename.c_str() << std::endl;
#endif
        std::ifstream infile(filename.c_str(), std::ios::in);
        if (!infile.good()) {
            syslog(LOG_ERR, " Could not open file room definitions ");
            std::cerr << thread_id << " Could not open file room definitions: " << filename.c_str() << std::endl;
            exit(1);
        }
#ifdef E2DEBUG
        std::cerr << thread_id << " Opened room file : " << filename.c_str() << std::endl;
#endif

        std::string roomname;
#ifdef E2DEBUG
        std::cerr << thread_id << " Reading room file : " << filename.c_str() << std::endl;
#endif
        getline(infile, roomname);
        if (infile.eof()) {
            syslog(LOG_ERR, " Unexpected EOF ");
            std::cerr << thread_id << " Unexpected EOF: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (infile.fail()) {
            syslog(LOG_ERR, " Unexpected failure on read");
            std::cerr << thread_id << " Unexpected failure on read: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (infile.bad()) {
            syslog(LOG_ERR, " Unexpected badbit failure on read");
            std::cerr << thread_id << " Unexpected badbit failure on read: " << filename.c_str() << std::endl;
            exit(1);
        }
        if (!infile.good()) {
            syslog(LOG_ERR, " Could not open file room definitions ");
            std::cerr << thread_id << " Could not open file room definitions: " << filename.c_str() << std::endl;
            exit(1);
        }
#ifdef E2DEBUG
        std::cerr << thread_id << " Room name is: " << roomname.c_str() << std::endl;
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
                    if (sitelist->ifsReadSortItemList(&infile, "", "", true, "#ENDLIST", false, false, 0, filename.c_str())) {
                        this_room.sitelist = sitelist;
                    } else {
                        delete sitelist;
                    }
                } else if (temp.startsWith("#URLLIST")) {
                    ListContainer *urllist = new ListContainer();
                    if (urllist->ifsReadSortItemList(&infile,"", "",  true, "#ENDLIST", false, true, 0, filename.c_str())) {
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
                std::cerr << thread_id << "Could not read room from definitions file \"" << filename << '"' << std::endl;
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

#ifdef NOTDEF
bool LOptionContainer::realitycheck(long int l, long int minl, long int maxl, const char *emessage)
{
    // realitycheck checks an amount for certain expected criteria
    // so we can spot problems in the conf files easier
    if ((l < minl) || ((maxl > 0) && (l > maxl))) {
        if (!is_daemonised) {
            // when called we have not detached from
            // the console so we can write back an
            // error

            std::cerr << thread_id << "Config problem; check allowed values for " << emessage << std::endl;
        }
        syslog(LOG_ERR, "Config problem; check allowed values for %s", emessage);
        return false;
    }
    return true;
}
#endif

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
                std::cerr << thread_id << "Error opening group names file: " << group_names_list_location << std::endl;
            syslog(LOG_ERR, "Error opening group names file: %s", group_names_list_location.c_str());
            return false;
        }
    }
    for (int i = 1; i <= o.filter_groups; i++) {
        file = prefix;
        file += String(i);
        file += ".conf";
        if (o.use_group_names_list) {
            std::ostringstream groupnum;
            groupnum << i;
            groupname = groupnamesfile[groupnum.str().c_str()];
            if (groupname.length() == 0) {
                if (!is_daemonised)
                    std::cerr << thread_id << "Group names file too short: " << group_names_list_location << std::endl;
                syslog(LOG_ERR, "Group names file too short: %s", group_names_list_location.c_str());
                return false;
            }
#ifdef E2DEBUG
            std::cerr << thread_id << "Group name: " << groupname << std::endl;
#endif
        }
        if (!readAnotherFilterGroupConf(file.toCharArray(), groupname.toCharArray(), need_html, i)) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error opening filter group config: " << file << std::endl;
            }
            syslog(LOG_ERR, "Error opening filter group config: %s", file.toCharArray());
            return false;
        }
    }
    return true;
}

bool LOptionContainer::readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html, int fg_no)
{
#ifdef E2DEBUG
    std::cerr << thread_id << "adding filter group: " << numfg << " " << filename << std::endl;
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

#ifdef E2DEBUG
    std::cerr << thread_id << "added filter group: " << numfg << " " << filename << std::endl;
#endif

    // pass all the vars from OptionContainer needed
    (*fg[numfg]).weighted_phrase_mode = o.weighted_phrase_mode;
    (*fg[numfg]).force_quick_search = o.force_quick_search;
    (*fg[numfg]).reverse_lookups = o.reverse_lookups;

    // pass in the group name
    (*fg[numfg]).name = groupname;

    // pass in the group number
    (*fg[numfg]).filtergroup = fg_no;

    // pass in the reporting level - can be overridden
    (*fg[numfg]).reporting_level = reporting_level;

#ifdef E2DEBUG
    std::cerr << thread_id << "passed variables to filter group: " << numfg << " " << filename << std::endl;
#endif

    bool rc = (*fg[numfg]).read(filename);
#ifdef E2DEBUG
    std::cerr << thread_id << "read filter group: " << numfg << " " << filename << " return is " << rc << std::endl;
#endif

    numfg++;

    if (!rc) {
        return false;
    }
    return true;
}
