// SBFunction class 

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_SBFN
#define __HPP_SBFN

// INLCUDES

#include <vector>
#include <deque>
#include <map>
#include <string>
#include "String.hpp"
#include "RegExp.hpp"
#include "ListMeta.hpp"

// commands 
#define  SB_COM_STARTFUNCTION	1
#define  SB_COM_ENDFUNCTION	2
#define  SB_COM_IF		3
#define  SB_COM_IFNOT		4

//  STATES indicates test to be performed

// xIN states takes list as argument and checks if x is in list
#define SB_STATE_URLIN		1
#define SB_STATE_SITEIN		2
#define SB_STATE_SEARCHIN	3
#define SB_STATE_EMBEDDEDIN	4
#define SB_STATE_REFERERIN	5
#define SB_STATE_HEADERIN	6
#define SB_STATE_FULLURLIN	 7
#define SB_STATE_EXTENSIONIN	 8
#define SB_STATE_MIMEIN	 9
#define SB_STATE_CLIENTIN	 10

#define SB_STATE_TOPIN      11   // all below this require a valid list

// Check type of request
#define SB_STATE_CONNECT	11
#define SB_STATE_POST			12
#define SB_STATE_GET				13
#define SB_STATE_SITEISIP       14
#define SB_STATE_TLS				15

// xSET check setting of flag x
#define SB_STATE_EXCEPTIONSET	16
#define SB_STATE_GREYSET	17
#define SB_STATE_BLOCKSET	18
#define SB_STATE_MITMSET        19
#define SB_STATE_DONESET       20
#define SB_STATE_RETURNSET       21
#define SB_STATE_TRUE				22
#define SB_STATE_HASSNI			23

#define SB_STATE_MAP_SIZE  23

// Storyboard defined functions IDs start at 1 - Built-in actions at 5001
#define SB_BI_FUNC_BASE		5000

// BUILT_IN functions
#define SB_FUNC_SETEXCEPTION	    5001
#define SB_FUNC_SETGREY		            5002
#define SB_FUNC_SETBLOCK	            5003
#define SB_FUNC_SETMODURL			5004
#define SB_FUNC_SETDONE		            5005
#define SB_FUNC_SETTRUE		            5006
#define SB_FUNC_SETFALSE		        5007
#define SB_FUNC_SETGOMITM            5008
#define SB_FUNC_SETLOGCAT            5009
#define SB_FUNC_SETADDHEADER   5010
#define SB_FUNC_SETREDIRECT        5011
#define SB_FUNC_SETNOCHECKCERT 5012
#define SB_FUNC_SETSEARCHTERM 5013
#define SB_FUNC_SETMODHEADER   5014

#define SB_FUNC_MAP_SIZE  14


// DECLARATIONS

class SBFunction
{
 private:
   String state_map[SB_STATE_MAP_SIZE] = {
             "urlin",
			"sitein",
			"searchin",
			"embeddedin",
             "refererin",
			 "headerin",
			 "fullurlin",
			 "extensionin",
			 "mimein",
			 "clientin",
			"connect",
			 "post",
			 "get",
			 "siteip",
			 "tls",
			"exceptionset",
			"greyset",
			"blockset",
			"mitmset",
			"doneset",
			"returnset",
			 "true",
			 "hassniset"
			};
   String command_map[4] = { "function",
			"end",
			"if",
			"ifnot",
			};

    std::vector<String> bi_funct_map = {
             "setexception",
             "setgrey",
            "setblock",
			"setmodurl",
            "setdone",
			"true",
			"false",
            "setgomitm",
            "setlogcategory",
            "setaddheader",
            "setredirect",
            "setnocheckcert",
			"setsearchterm",
			 "setmodheader"
    };

  public:
    int items;


	struct com_rec {
		bool isif = false;   // true if if  - false is ifnot
		unsigned int state;	// what is being tested e.g. url site search etc
		std::deque<ListMeta::list_info> list_id_dq;   // holds ids of list(s) being used
		unsigned int mess_no = 0;   // optional overide of list defaults
		unsigned int log_mess_no = 0;   // optional overide of list defaults
		unsigned int action_id;     // action to take if result true
		bool return_after_action = false;
		bool return_after_action_is_true = false;
		bool optional = false;     //  if true do not abort if lists do not exist
		unsigned int file_lineno;   // used for debug output
		String action_name; 	    // name of action
		String list_name;	    // name of list
	};

    String name;
    unsigned int fn_id;
    std::deque<com_rec> comm_dq;
    String file_name;	// holds source file path for debug
    unsigned int file_lineno;   // used for debug output

    SBFunction();
    ~SBFunction();

    void reset();
	bool start(String & name, unsigned int id, unsigned int& line_noi, String filename);
	bool end();
	bool addline(String command, String params, String action, unsigned int line_no);
	unsigned int getStateID(String & state);
    unsigned int getBIFunctID(String & action);
    String getState(unsigned int id);
	String getBIFunct(unsigned int &id);
	String getName();


};

#endif
