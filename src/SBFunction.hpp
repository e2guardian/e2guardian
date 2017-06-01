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

#define SB_STATE_TOPIN      5   // all below this require a valid list

// Check type of request
#define SB_STATE_CONNECT	5

// xSET check setting of flag x
#define SB_STATE_EXCEPTIONSET	6
#define SB_STATE_GREYSET	7
#define SB_STATE_BLOCKSET	8
#define SB_STATE_MITMSET        9
#define SB_STATE_DONESET       10

#define SB_STATE_MAP_SIZE  10

// BUILT_IN functions
#define SB_FUNC_SETEXCEPTION	    5001
#define SB_FUNC_SETGREY		            5002
#define SB_FUNC_SETBLOCK	            5003
#define SB_FUNC_SETDONE		            5004

#define SB_FUNC_MAP_SIZE  4

// Defined functions IDs start at 51
#define SB_BI_FUNC_BASE		5000


// DECLARATIONS

class SBFunction
{
 private:
   String state_map[SB_STATE_MAP_SIZE] = { "urlin",
			"sitein",
			"searchin",
			"embeddedin",
			"connect",
			"exceptionset",
			"greyset",
			"blockset",
			"mitmset",
			"doneset",
			};
   String command_map[4] = { "startfunction",
			"endfunction",
			"if",
			"ifnot",
			};

    String bi_funct_map[SB_FUNC_MAP_SIZE] = {
            "setexception",
            "setgrey",
            "setblock",
            "setdone",
    };

  public:
    int items;


    struct com_rec {
	bool isif;   // true if if  - false is ifnot
	unsigned int state;	// what is being tested e.g. url site search etc
	std::deque<unsigned int> list_id_dq;   // holds ids of list(s) being used
	unsigned int mess_no;   // optional overide of list defaults
	unsigned int log_mess_no;   // optional overide of list defaults
	unsigned int action_id;     // action to take if result true
		bool return_after_action;
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
	bool start(String & name, unsigned int id, unsigned int& line_no);
	bool end();
	bool addline(String command, String params, String action, unsigned int line_no);
	unsigned int getStateID(String & state);
    unsigned int getBIFunctID(String & action);


};

#endif
