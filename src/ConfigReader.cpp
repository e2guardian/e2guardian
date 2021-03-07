// Implements the ConfigReader class

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "ConfigReader.hpp"

#include <fstream>
#include <map>

#include "Logger.hpp"
#include "String.hpp"

// IMPLEMENTATION
const char* DELIMITER1 = "=";  // delimites option  and value e.g option = value
const char* DELIMITER2 = ":";  // delimits multiple values e.g. value1 : value2 : value3

#pragma region  ConfigReaderImpl
class ConfigReaderImpl
{
  public:
    void addOption(String line);
    std::deque<String> * getOption(std::string optionName);

  private:
    std::map<std::string, std::deque<String>> options;
    std::deque<String> empty;
    void add(String option, String value);
};



void ConfigReaderImpl::addOption(String line) 
{
  String name = line.before(DELIMITER1);
  String values = line.after(DELIMITER1);

  while (name.endsWith(" ")) { // get rid of tailing spaces before =
      name.chop();
  }
  if ( name.empty() ) return;
  while (values.contains(DELIMITER2)) {
    String t = values.before(DELIMITER2);
    add(name, t);
    values = values.after(DELIMITER2);
  }
  add(name, values);
}

std::deque<String> * ConfigReaderImpl::getOption(std::string optionName) 
{
  if (options.count(optionName) > 0)
  {
    return & options[optionName];
  }
  else
  {
    return & empty;
  }
  
}

void ConfigReaderImpl::add(String option, String value)
{
  while (value.startsWith(" ")) { // get rid of heading spaces
      value.lop();
  }
  if (value.startsWith("'")) { // inverted commas
      value.lop();
  }
  while (value.endsWith(" ")) { // get rid of tailing spaces
      value.chop();
  }
  if (value.endsWith("'")) { // inverted commas
      value.chop();
  }
  if (value.empty()) return;

  std::deque<String> entry = options[option.c_str()];
  entry.push_back(value.c_str());
  options[option.c_str()] = entry;
}

#pragma endregion


// PUBLIC

// constructor
ConfigReader::ConfigReader() : pImpl( new ConfigReaderImpl )
{
}
ConfigReader::~ConfigReader() {
  delete pImpl;
}

// construct & read in the given config file
ConfigReader::ConfigReader(const Path &filename, const Path &list_pwd)
{
   readConfig(filename, list_pwd );
}

// method readConfig
bool ConfigReader::readConfig(const Path &filename, const Path &list_pwd) {

    Path base_dir = filename.baseDir();
    std::string now_pwd = list_pwd.fullPath();
    std::string linebuffer;

    std::ifstream conffile(filename.fullPath(), std::ios::in); // e2guardian.conf
    if (!conffile.good()) {
        E2LOGGER_error("Error reading ", filename.fullPath());
        return false;
    }

    while (!conffile.eof()) {
      getline(conffile, linebuffer);
      if (!conffile.fail() && linebuffer.length() != 0) {
        String temp = (char *) linebuffer.c_str();
        if (linebuffer[0] == '#') {          
          continue;   // skip comment line
        }
        else if (linebuffer[0] == '.') {
          String filename = temp.after(".Include<").before(">");
          if (filename.length() > 0) {
              if (!readConfig( base_dir.combine(filename), now_pwd)) {
                  conffile.close();
                  return false;
              }
          }
          temp = temp.after(".Define LISTDIR <").before(">");
          if (temp.length() > 0) {
              now_pwd = temp;
              if(now_pwd.back() != '/')
                  now_pwd += "/";
          }
        } 
        else
        {
          if (temp.contains("#")) {
            temp = temp.before("#");  // remove trailing comment
          }
          temp.removeWhiteSpace(); // get rid of spaces at end of line
          if (temp.contains("__LISTDIR__")) {
              temp.replaceall("__LISTDIR__", now_pwd.c_str());
          }
          // append ,listdir=now_pwd if line contains a file path - so that now_pwd can be passed
          // to list file handler so that it can honour __LISTDIR__ in Included listfiles
          if (temp.contains("path=") && !temp.contains("listdir=")) {
              temp += ",listdir=";
              temp += now_pwd;
          }
          
        }
        
        DEBUG_config("read:", temp);
        pImpl->addOption(temp); // store option 
      }        
    }
    conffile.close();
    return true;
}

// findoptionM returns all instances of an option 
std::deque<String>* ConfigReader::findoptionM(const char *option)
{
  return pImpl->getOption(option);
}

std::string ConfigReader::findoptionS(const char *option)
{
  std::deque<String>* values = findoptionM(option);
  if ( values && values->size() > 0 )
    return findoptionM(option)->back();
  else
    return "";  
}

bool ConfigReader::findoptionB(const char *option)
{
  std::string ok = findoptionS(option);
  if (ok=="ok" || ok == "yes") return true;
  return false;
} 

long int ConfigReader::findoptionI(const char *option)
{
  std::string number = findoptionS(option);
  if ( number != "")
    return std::stol(number);
  else
    return 0;  
}

// findoptionIWithDefault gets an option value, checks for minl and maxl bounds and defaults to defaultl if no value was found
long int ConfigReader::findoptionIWithDefault(const char * option, long int minl, long int maxl, long int defaultl)
{
    std::string s = findoptionS(option);
    if ( s == "" ) return defaultl;
    long int value = std::stol(s);

    if ((value < minl) || ((maxl > 0) && (value > maxl))) {
        E2LOGGER_error("Config problem; check allowed values for ", option, "( ", value , " should be >= ", minl, " <=", maxl, ")",
                    "we are using default value:", defaultl);        
        return defaultl;
    }
    return value;
}
