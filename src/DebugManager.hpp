//INCLUDES

#ifndef __HPP_DebugManager
#define __HPP_DebugManager

#include <iostream>
#include <string>

//DECLARATIONS

class DebugManager
{
	private:
		std::string m_debuglevel;
	public:
		DebugManager(std::string);
		~DebugManager();
		void Debug(std::string value, std::string output);
};
#endif
