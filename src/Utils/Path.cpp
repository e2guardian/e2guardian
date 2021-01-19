// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "Path.hpp"

Path::~Path()
{
}

Path Path::baseDir() const
{
    size_t fnsize;
    if ((fnsize = _path.find_last_of("/")) > 0)
      return Path(_path.substr(0,++fnsize));
    else
      return Path("");    
}

void Path::append(const Path &relative_path) {
  _path += relative_path._path;
}

Path Path::combine(const Path &relative_path) {
  Path temp(*this);
  temp.append(relative_path);
  return temp;
}
