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

// Check type of request
#define SB_STATE_CONNECT	5

// xSET check setting of flag x
#define SB_STATE_EXCEPTIONSET	6
#define SB_STATE_GREYSET	7
#define SB_STATE_BLOCKSET	8
#define SB_STATE_MITMSET        9
#define SB_STATE_DONESET       10

// BUILT_IN functions
#define SB_FUNC_SETEXCEPTION	1
#define SB_FUNC_SETGREY		2
#define SB_FUNC_SETBLOCK	3
#define SB_FUNC_SETDONE		4

// Defined functions IDs start at 51
#define SB_DEFFUNC_BASE		51


// DECLARATIONS

class StoryBoard
{
 private:
   String state_map[] = { "urlin",
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
   String command_map[] = { "startfunction",
			"endfunction",
			"if",
			"ifnot",
			};

  public:
    int items;

    struct fn_rec{
        String name;
        unsigned int fn_id;
        std::deque<com_rec> comm_dq;
	String file_name;	// holds source file path for debug
	unsigned int file_lineno;   // used for debug output
    };

    struct com_rec{
	bool isif;   // true if if  - false is ifnot
	unsigned int state;	// what is being tested e.g. url site search etc
	unsigned int list_id;   // id of list being used
	unsigned int mess_no;   // optional overide of list defaults
	unsigned int log_mess_no;   // optional overide of list defaults
	unsigned int action_id;     // action to take if result true
	unsigned int file_lineno;   // used for debug output
	String action_name; 	    // name of action
	String list_name;	    // name of list
     };

    std::vector<fn_rec> funct_vec;

    StoryBoard();
    ~StoryBoard();

    void reset();


   bool readFile(const char *filename, unsigned int *whichlist, bool sortsw, const char *listname);

};

#endif
