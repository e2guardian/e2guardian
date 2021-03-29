// Class Path : methods on strings which represents the path of file or directory
// 
// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_PATH
#define __HPP_PATH

// INCLUDES

#include <iostream>
#include <string>
#include <sys/types.h>

// DECLARATIONS

class Path 
{
  private:
    std::string _path;

  public:
    Path() { _path = ""; };
    ~Path();

    // properties
    std::string fullPath() const { return _path; }

    // constructor from c-string
    Path(const char *bs)    { _path = bs; };
    // constructor from std-string
    Path(std::string ss)    { _path = ss; };
    // copy constructor
    Path(const Path &p)     { _path = p._path; };

    // return to base dir (for file paths)
    Path baseDir() const;
    
    // appends to this base dir a relative_path
    void append(const Path &relative_path);

    // combines this base dir and a relative_path
    Path combine(const Path &relative_path);

};
#endif
