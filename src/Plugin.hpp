// the Plugin interface - inherit this to define new plugin types

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_PLUGIN
#define __HPP_PLUGIN


// INCLUDES


// DECLARATIONS

class Plugin
{
public:
	virtual ~Plugin(){};
	
	// plugin initialise/quit routines.
	// return 0 for OK, < 0 for error, > 0 for warning
	virtual int init(void* args) = 0;
	virtual int quit() = 0;
};

#endif
