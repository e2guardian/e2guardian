//INCLUDES

#include "DebugManager.hpp"

//IMPLEMENTATION

DebugManager::DebugManager(std::string debuglevel, std::string path_debuglevel)
{
	m_debuglevel = debuglevel;
	m_path_debuglevel = path_debuglevel;
	if(m_debuglevel != "" && m_path_debuglevel != "")
	{
		pFile = fopen(m_path_debuglevel.c_str(),"w");
		if(pFile != NULL)
		{
			m_e2debug = true;
			fclose(pFile);
		}
		else
		{
			openlog("e2guardian", LOG_PID | LOG_CONS, LOG_USER);
			syslog(LOG_INFO, "cannot open or create the debuglevelfile : %s",m_path_debuglevel.c_str());
			closelog();
		}
	}
	else
	{
		m_e2debug = false;
	}
}

DebugManager::~DebugManager()
{
}

void DebugManager::Debug(std::string value, std::string output)
{
	if (value != "" && m_e2debug == true)
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
			pFile = fopen(m_path_debuglevel.c_str(),"w");
			if(pFile != NULL)
			{
				std::ostringstream oss (std::ostringstream::out);
				oss << result << " debug : " << output << std::endl;
				fputs(oss.str().c_str(),pFile);
				fclose(pFile);
			}
		}
	}
	else
	{
			std::cerr << "error value of the debug level, please check your /etc/e2guardian/e2guardian.conf file !" << std::endl;
	}
}

bool DebugManager::gete2debug()
{
	return m_e2debug;
}
