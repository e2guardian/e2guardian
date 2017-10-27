//INCLUDES

#include "DebugManager.hpp"
#include <vector>

//IMPLEMENTATION

DebugManager::DebugManager(std::string debuglevel)
{
	m_debuglevel = debuglevel;
}

DebugManager::~DebugManager()
{
}

void DebugManager::Debug(std::string value, std::string output)
{
	if (value != "" && m_debuglevel != "")
	{	
		std::string v = value;
		std::vector<std::string> liste;
		std::string result = "";	
		if(v.find(",") != std::string::npos)
		{
			while(v.find(",") != std::string::npos)
			{
				liste.push_back(v.substr(0,v.find(",")));
				v = v.substr(v.find(",")+1);
			}
		}
		liste.push_back(v);
	
		for(int i = 0; i < liste.size(); i++)
		{
			if(m_debuglevel.find("ALL,") == 0 && m_debuglevel.find("," + liste[i]) == std::string::npos)
			{
				result = liste[i];		
			}
			else if(m_debuglevel == "ALL" || m_debuglevel == liste[i])
	                {       
        	         	result = liste[i];       
	                }
			else if(m_debuglevel.find("ALL") == std::string::npos && m_debuglevel.find(liste[i]) != std::string::npos)          
                	{
	                    	result = liste[i];
                 	}

		}

		if(result != "")
		{
			std::cout << result << " debug : " << output << std::endl;
		}
	}
	else
	{
			std::cout << "error value of the debug level, please check your /etc/e2guardian/e2guardian.conf file !" << std::endl;
	}
}
