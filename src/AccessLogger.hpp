// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_ACCESSLOGGER
#define __HPP_ACCESSLOGGER

// INCLUDES
#include "String.hpp"
#include "Logger.hpp"
#include "Queue.hpp"
#include "NaughtyFilter.hpp"

// DECLARATIONS

namespace AccessLogger {

  // record for storing information about POST data parts
  // used for building up the POST data log column
  struct postinfo {
      // MIME type & original filename (if available)
      std::string mimetype;
      std::string filename;
      // name of file containing headers & body info
      // for this POST part (if it has been stored)
      std::string storedname;
      // size of part
      size_t size;
      // offset of body data from start of file
      // (if post part was stored on disk)
      size_t bodyoffset;
      bool blocked;
      postinfo()
          : size(0), bodyoffset(0), blocked(false){};
  };


  struct LogRecord {
    bool is_RQlog = false;
    String where;
    String what;
    String how;
    String who;
    String from;
    String category;
    bool isexception;
    bool isnaughty;
    int naughtytype;
    int naughtiness;
    unsigned int port;
    bool wasscanned;
    bool wasinfected;
    bool contentmodified;
    bool urlmodified;
    bool headermodified;
    bool headeradded;
    off_t size;
    int filtergroup;
    String filtergroupname;

    int code;
    bool cachehit;
    String mimetype;
    struct timeval thestart;
    struct timeval theend;
    String clientip;
    String clienthost;
    String useragent;
    String urlparams;
    String postdata;
    int message_no;
    String flags;
    String search_terms;

    String getFormatted(const std::string format, const char delimiter);
    String getPart(const std::string part);

    String getFormat1();
    String getFormat2();
    String getFormat3();
    String getFormat4();
    String getFormat5();
    String getFormat7();

    struct Helper;
  };

  void log_listener(Queue<LogRecord*> &log_Q, bool is_RQlog);

  void doLog(std::string &who, std::string &from, NaughtyFilter &cm, std::list<AccessLogger::postinfo> *postparts, std::string urlparams);
  void doRQLog(std::string &who, std::string &from, NaughtyFilter &cm, std::string &funct);

  void shutDown();
}

#endif