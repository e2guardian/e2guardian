//INCLUDES

#include "DebugManager.hpp"

//IMPLEMENTATION

DebugManager::DebugManager(std::string debuglevel, std::string path_debuglevel)
{
	m_debuglevel = debuglevel;
	m_path_debuglevel = path_debuglevel;
	if(m_debuglevel != "" && m_path_debuglevel != "")
	{
		pFile = fopen(m_path_debuglevel.c_str(),"a");
		if(pFile != NULL)
		{
			LoadParam();
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
	fclose(pFile);
}

void DebugManager::Debug(std::string value, std::string output,...)
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
	
		for(unsigned int i = 0; i < liste.size(); i++)
		{
			if(m_debuglevel.find("ALL,") == 0 && (m_debuglevel.find("," + liste[i]) == std::string::npos || !Filter(liste[i])))
			{
				result = liste[i];		
			}
			else if(m_debuglevel == "ALL" || m_debuglevel == liste[i])
	                {       
        	         	result = liste[i];       
	                }
			else if(m_debuglevel.find("ALL") == std::string::npos && (m_debuglevel.find(liste[i]) != std::string::npos || Filter(liste[i])))          
                	{
	                    	result = liste[i];
                 	}
		}

		if(result != "")
		{
			if(pFile != NULL)
			{
				std::ostringstream oss (std::ostringstream::out);
				oss << thread_id << time(NULL) << " " << result << " debug : ";
				
				int i=0;
				unsigned int j=0;
				va_list ap;
				va_start(ap,output);
				char * p = new char[output.length()+1]; 
				strcpy(p,output.c_str());
				char buff[2000];
				char * v = buff;
				int n;
				while(*(p+i)!='\0')
				{
					switch(*(p+i))
					{
						case '%': 
							i++;
							if(*(p+i)=='c')
							{
								oss << va_arg(ap,int);
							}

							if(*(p+i)=='d')	
							{ 
								n = va_arg(ap,int);
								std::stringstream ss;
								ss << n;
								std::string tmp = ss.str();
								strcpy(v,tmp.c_str());

								for(j=0;j<strlen(v);j++)
								{
									oss << v[j];
								}
							}
							if(*(p+i)=='s')
							{ 
								v = va_arg(ap,char *);
								for(j=0;j<strlen(v);j++)
								{
									oss << v[j];
								}
							}
							break;
						default :
							oss << *(p+i); 
							break;
					}
					i++;
				}
				va_end(ap);
				oss << std::endl;
				fputs(oss.str().c_str(),pFile);
			}
		}
	}
	else
	{
			std::cerr << "error value of the debug level, please check your /etc/e2guardian/e2guardian.conf file !" << std::endl;
	}
}

void DebugManager::LoadParam()
{
	m_e2debug = true;
	std::string v = m_debuglevel;
	std::vector<std::string> liste;
	if(v.find(",") != std::string::npos)
	{
		while(v.find(",") != std::string::npos)
		{
			liste.push_back(v.substr(0,v.find(",")));
			v = v.substr(v.find(",")+1);
		}
	}
	liste.push_back(v);

	bool checkall = false;
	bool checkfilter = false;

	bool checkicap = false;
	bool checkicapc = false;
	bool checkclamav = false;
	bool checkthttps = false;
	bool checkproxy = false;
	for(unsigned int i = 0; i < liste.size(); i++)
	{
		if(liste[i].find("ALL") != std::string::npos)
		{
			if(liste[i].find("-") == std::string::npos)
			{
				ICAP = true;
				ICAPC = true;
				CLAMAV = true;
				THTTPS = true;
				PROXY = true;
			}
			else
			{
				ICAP = false;
				ICAPC = false;
				CLAMAV = false;
				THTTPS = false;
				PROXY = false;
			}
			CheckFlag(checkall);
			checkall = true;	
		}
		if(liste[i].find("FILTER") != std::string::npos)
		{
			if(liste[i].find("-") == std::string::npos)
			{
				ICAP = true;
				ICAPC = true;
				THTTPS = true;
				PROXY = true;
			}
			else
			{
				ICAP = false;
				ICAPC = false;
				THTTPS = false;
				PROXY = false;
			}
			CheckFlag(checkfilter);
			checkfilter = true;
		}	
		if(liste[i].find("ICAP") != std::string::npos)
		{
			if(liste[i].find("-") == std::string::npos)
			{
				ICAP = true;
			}
			else
			{
				ICAP = false;
			}
			CheckFlag(checkicap);
			checkicap = true;
		}
                if(liste[i].find("ICAPC") != std::string::npos)
                {
                        if(liste[i].find("-") == std::string::npos)
                        {
                                ICAPC = true;
                        }
                        else
                        {
                                ICAPC = false;
                        }
                        CheckFlag(checkicapc);
                        checkicap = true;
                }

		if(liste[i].find("CLAMAV") != std::string::npos)
		{
			if(liste[i].find("-") == std::string::npos)
			{
				CLAMAV = true;
			}
			else
			{
				CLAMAV = false;
			}
			CheckFlag(checkclamav);
			checkclamav = true;
		}
		if(liste[i].find("THTTPS") != std::string::npos)
		{
			if(liste[i].find("-") == std::string::npos)
			{
				THTTPS = true;
			}
			else
			{
				THTTPS = false;
			}
			CheckFlag(checkthttps);
			checkthttps = true;
		}
		if(liste[i].find("PROXY") != std::string::npos)
		{
			if(liste[i].find("-") == std::string::npos)
			{
				PROXY = true;
			}
			else
			{
				PROXY = false;
			}
			CheckFlag(checkproxy);
			checkproxy = true;
		}
	}
}

void DebugManager::CheckFlag(bool flag)
{
	if(flag)
	{
		openlog("e2guardian", LOG_PID | LOG_CONS, LOG_USER);
		syslog(LOG_INFO, "WARNING : Ambiguous syntax of debuglevel in e2guardian.conf");
		closelog();
	}
}

bool DebugManager::Filter(std::string s)
{
	if(m_debuglevel.find("FILTER") != std::string::npos && (s.find("ICAP") != std::string::npos || s.find("THTTPS") != std::string::npos || s.find("PROXY") != std::string::npos))
	{
		return true;
	}
	else
	{
		return false;
	}
}
