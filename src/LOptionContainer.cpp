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
#include "Logger.hpp"

//#include <cstdio>
//#include <iostream>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <cstdlib>

// GLOBALS

extern OptionContainer o;

// IMPLEMENTATION

LOptionContainer::LOptionContainer()
{
}

LOptionContainer::LOptionContainer(int load_id)
{
    e2logger_trace("load_id: ", load_id);

    char buff[40];

    sprintf(buff, "%ld", time(NULL));
    start_time = buff;

    loaded_ok = true;

    {
        e2logger_config("iplist size is ", o.iplist_dq.size());
        if(!LMeta.load_type(LIST_TYPE_IP, o.iplist_dq))
            loaded_ok = false;
    }

    {
        e2logger_config("sitelist size is ", o.sitelist_dq.size());
        if(!LMeta.load_type(LIST_TYPE_SITE, o.sitelist_dq))
            loaded_ok = false;
    }

    {
        e2logger_config("ipsitelist size is ", o.ipsitelist_dq.size());
        if(!LMeta.load_type(LIST_TYPE_IPSITE, o.ipsitelist_dq))
            loaded_ok = false;
    }

    {
        e2logger_config("urllist size is ", o.urllist_dq.size());
        if(!LMeta.load_type(LIST_TYPE_URL, o.urllist_dq))
            loaded_ok = false;
    }

    {
        e2logger_config("regexpboollist size is ", o.regexpboollist_dq.size());;
        if(!LMeta.load_type(LIST_TYPE_REGEXP_BOOL, o.regexpboollist_dq))
            loaded_ok = false;
    }

    {
        e2logger_config("maplist size is ", o.maplist_dq.size());
        if(!LMeta.load_type(LIST_TYPE_MAP, o.maplist_dq))
            loaded_ok = false;
    }

    {
        e2logger_config("ipmaplist size is ", o.ipmaplist_dq.size());
        if(!LMeta.load_type(LIST_TYPE_IPMAP, o.ipmaplist_dq))
            loaded_ok = false;
    }

    e2logger_config("read Storyboard: ", o.storyboard_location);
    if (!StoryA.readFile(o.storyboard_location.c_str(), LMeta, true)) {
        e2logger_error("Storyboard not loaded OK");
        loaded_ok = false;
    }

    if (loaded_ok && !StoryA.setEntry(ENT_STORYA_PRE_AUTH,"pre-authcheck")) {
        e2logger_error("Required storyboard entry function 'pre-authcheck' is missing");
        loaded_ok = false;
    }

    if (loaded_ok && (o.transparenthttps_port > 0) && !StoryA.setEntry(ENT_STORYA_PRE_AUTH_THTTPS,"thttps-pre-authcheck")) {
        e2logger_error("Required storyboard entry function 'thttps-pre-authcheck' is missing");
        loaded_ok = false;
    }

    if (loaded_ok && (o.icap_port > 0) && !StoryA.setEntry(ENT_STORYA_PRE_AUTH_ICAP,"icap-pre-authcheck")) {
        e2logger_error("Required storyboard entry function 'icap-pre-authcheck' is missing");
        loaded_ok = false;
    }

 //   if (loaded_ok && o.use_filter_groups_list)  {
 //       if (!doReadItemList(o.filter_groups_list_location.c_str(), &filter_groups_list, "filtergroupslist", true)) {
 //           e2logger_error("Failed to read filtergroupslist");
 //           loaded_ok = false;
 //       }
 //   }

    e2logger_trace("Done reading Storyboard!");
    
    if (loaded_ok && o.auth_entry_dq.size() > 0)  {
            for (std::deque<struct OptionContainer::SB_entry_map>::const_iterator i = o.auth_entry_dq.begin(); i != o.auth_entry_dq.end(); ++i) {
                if (!StoryA.setEntry(i->entry_id, i->entry_function)) {
                    e2logger_error("Required auth storyboard entry function", i->entry_function,
                                " is missing from pre_auth.stoary");
                    loaded_ok = false;
                }
            }
    }

    if(loaded_ok && (!readFilterGroupConf() || (o.abort_on_missing_list && o.config_error)))  {
        loaded_ok = false;
        e2logger_error("Error in reading filter group files");
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

    e2logger_trace("inURLList");
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

    e2logger_debug("inURLList (processed): ", url);
    while (url.before("/").contains(".")) {
        i = lc->findStartsWith(url.toCharArray(), lastcategory);
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
            e2logger_debug("foundurl: ", foundurl, ":", foundurl.length());
            e2logger_debug("url: ", url, ":", fl);
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
        e2logger_error("Error opening ", fname);
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
            e2logger_debug(" IP is in room: ", i->name);
            temp = url;
            ListContainer *lc;
            if (i->sitelist) {
                lc = i->sitelist;
                if (inSiteList(temp, lc, false, false)) {
                    e2logger_debug(" room site exception found: ");
                    *isexception = true;
                    room = i->name;
                    return true;
                }
            }
            temp = url;
            if (i->urllist && inURLList(temp, i->urllist, false, false)) {
                e2logger_debug(" room url exception found: ");
                *isexception = true;
                room = i->name;
                return true;
            }
            if (i->block) {
                *block = true;
                *part_block = i->part_block;
                room = i->name;
                e2logger_debug(" room blanket block active: ");
                return true;
            } else {
                e2logger_debug(" room - no url/site exception or block found: ");
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
            e2logger_debug("In deleteFilterGroups loop");
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
bool LOptionContainer::readList(std::string& filename, int type, std::string& exception_ip_list_location,
                            std::string& banned_ip_list_location)
{
    e2logger_trace(filename);
    
	conffilename = filename;

	// all sorts of exceptions could occur reading conf files
	try {
		std::string linebuffer;
		String temp;  // for tempory conversion and storage
		std::ifstream conffiles(filename.c_str(), std::ios::in);  // e2guardian.conf
		if (!conffiles.good()) {
			e2logger_error("error reading e2guardian.conf");
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
            e2logger_debug("iplist deque is size ", dq.size());
            LMeta.load_type(LIST_TYPE_IP, dq);
        }

        {
            std::deque<String> dq = findoptionM("sitelist");
            e2logger_debug("sitelist deque is size ", dq.size());
            LMeta.load_type(LIST_TYPE_SITE, dq);
        }

        {
            std::deque<String> dq = findoptionM("ipsitelist");
            e2logger_debug("ipsitelist deque is size ", dq.size());
            LMeta.load_type(LIST_TYPE_IPSITE, dq);
        }

        {
            std::deque<String> dq = findoptionM("urllist");
            e2logger_debug("urllist deque is size ", dq.size());
            LMeta.load_type(LIST_TYPE_URL, dq);
        }

        if (!StoryA.readFile(o.storyboard_location.c_str(), LMeta, true))
            return false;

        if (!StoryA.setEntry1("pre-authcheck")) {
            e2logger_error("Required storyboard entry function 'pre-authcheck' is missing");
            return false;
        }

        if (!readFilterGroupConf()) {
            e2logger_error("Error reading filter group conf file(s).");
            return false;
        }

    } catch (std::exception &e) {
        e2logger_error(e.what());
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
            e2logger_error("Could not open room definitions directory: ", strerror(errno));
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
        e2logger_debug("Room file found : ", filename);
        std::ifstream infile(filename.c_str(), std::ios::in);
        if (!infile.good()) {
            e2logger_error(" Could not open file room definitions ");
            exit(1);
        }
        e2logger_debug("Opened room file : ", filename);

        std::string roomname;
        e2logger_debug(" Reading room file : ", filename);
        getline(infile, roomname);
        if (infile.eof()) {
            e2logger_error(" Unexpected EOF ", filename);
            exit(1);
        }
        if (infile.fail()) {
            e2logger_error(" Unexpected failure on read: ", filename);;
            exit(1);
        }
        if (infile.bad()) {
            e2logger_error(" Unexpected badbit failure on read: ", filename);
            exit(1);
        }
        if (!infile.good()) {
            e2logger_error(" Could not open file room definitions: ", filename);
            exit(1);
        }
        e2logger_debug(" Room name is: ", roomname);

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
            e2logger_error( "Could not read room from definitions file \"", filename, '"');
            exit(1);
        }
        roomname = roomname.substr(1); // remove leading '#'
    }

    if (closedir(d) != 0) {
        if (errno != EINTR) {
            e2logger_error("Could not close room definitions directory: ", strerror(errno));
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
        e2logger_error("Config problem; check allowed values for ", emessage);
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

    e2logger_config("read FilterGroups");
    if (o.use_group_names_list) {
        int result = groupnamesfile.readVar(group_names_list_location.c_str(), "=");
        if (result != 0) {
            e2logger_error("Error opening group names file: ", group_names_list_location);
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
                e2logger_error("Group names file too short: ", group_names_list_location);
                return false;
            }
            e2logger_debug("Group name: ", groupname);
        }
        if (!readAnotherFilterGroupConf(file.toCharArray(), groupname.toCharArray(), need_html)) {
            e2logger_error("Error opening filter group config: ", file);
            return false;
        }
    }
    return true;
}

bool LOptionContainer::readAnotherFilterGroupConf(const char *filename, const char *groupname, bool &need_html)
{
    e2logger_debug("adding filter group: ", numfg, " ", filename);

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

    e2logger_debug("added filter group: ", numfg, " ", filename);

    // pass all the vars from OptionContainer needed
    (*fg[numfg]).weighted_phrase_mode = o.weighted_phrase_mode;
    (*fg[numfg]).force_quick_search = o.force_quick_search;
    (*fg[numfg]).reverse_lookups = o.reverse_lookups;

    // pass in the group name
    (*fg[numfg]).name = groupname;

    // pass in the reporting level - can be overridden
    (*fg[numfg]).reporting_level = reporting_level;

    e2logger_debug("passed variables to filter group: ", numfg, " ", filename);

    bool rc = (*fg[numfg]).readFilterGroup(filename);
    e2logger_debug("reading filter group: ", numfg, " ", filename, " return is ", rc);

    numfg++;

    if (!rc) {
        return false;
    }
    return true;
}
