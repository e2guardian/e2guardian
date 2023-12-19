// Defines the ConfigReader class, which implements reading options from a file.
// Options are declared with:
//
// OptionName = OptionValue
//
// OptionName can not contain spaces
// some OptionNames may be declared multiple time
// else the last declaration of the option will be used
//
// OptionValue may be :
// - a string (may be limited with single quote ' )
// - a number (long)
// - a bool   (on/off)
// a string OptionValue may contain the macro __LISTDIR__ which gets replaced by the current __LISTDIR__ value
//
// Lines starting with # are comment lines
// Lines starting with . are special lines:
// .Define LISTDIR <dirname>    : sets the value of __LISTDIR__ to dirname
// .Include<filename>           : includes the content of filename


// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_CONFIGREADER
#define __HPP_CONFIGREADER

// INCLUDES
#include <cstring>
#include <deque>
#include "String.hpp"
#include "Utils/Path.hpp"

// DECLARATIONS
class ConfigReaderImpl;
class ConfigReader
{
  public:
    ConfigReader();
    ~ConfigReader();

    // read the given file, storing option/value for later retrival
    // Params : list_pwd : base directory when looking for lists definitions
    ConfigReader(const Path &filename, const Path &list_pwd);
    bool readConfig(const Path &filename, const Path &list_pwd);

    std::deque<String>* findoptionM(const char *option);
    std::deque<String> findoptionMD(const char *option, const char *delimiter);
    std::string findoptionS(const char *option);
    bool findoptionB(const char *option);
    int findoptionI(const char *option);
    int findoptionIWithDefault(const char * option, int minl, int maxl, int defaultl);


  private:
    ConfigReaderImpl * pImpl;
    String parseLine(std::string line);

};

#endif
