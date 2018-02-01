//INCLUDES

#ifndef __HPP_DebugManager
#define __HPP_DebugManager

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdio.h>
#include <syslog.h>
//DECLARATIONS

class DebugManager
{
	private:
		std::string m_debuglevel;
		std::string m_path_debuglevel;
		bool m_e2debug;
		FILE * pFile;
	public:
		DebugManager(std::string debuglevel, std::string path_debuglevel);
		~DebugManager();
		void Debug(std::string value, std::string output);
		bool gete2debug();
};
#endif
