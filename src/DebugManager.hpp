//INCLUDES

#ifndef __HPP_DebugManager
#define __HPP_DebugManager

#include <iostream>
#include <sstream>
#include <stdarg.h>
#include <string>
#include <string.h>
#include <vector>
#include <stdio.h>
#include <syslog.h>
//DECLARATIONS

extern thread_local std::string thread_id;

class DebugManager
{
	private:
		std::string m_debuglevel;
		std::string m_path_debuglevel;
		FILE * pFile;
		bool m_e2debug = false;
		void LoadParam();
		void CheckFlag(bool flag);
		bool Filter (std::string s);
	public:	
		bool ICAP = false;
		bool ICAPC = false;
		bool CLAMAV = false;
		bool THTTPS = false;
		bool PROXY = false;
		DebugManager(std::string debuglevel, std::string path_debuglevel);
		~DebugManager();
		void Debug(std::string value, std::string output,...);
};
#endif
