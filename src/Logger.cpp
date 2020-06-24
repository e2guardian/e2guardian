
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include <iostream>
#include <string>
#include <sstream>
#include <syslog.h>
#include "Logger.hpp"

using namespace std;

// -------------------------------------------------------------
// --- Constructor
// -------------------------------------------------------------
Logger::Logger() {
  Logger("Logger");
};
Logger::Logger(const char* logname)
{
  setName(logname);
}

Logger::~Logger() {
  closelog();
}

// -------------------------------------------------------------
// --- Helper
// -------------------------------------------------------------

struct Logger::Helper
{
  static std::string build_message(
      const std::string prepend,
      const std::string thread_id, 
      const std::string func, 
      const int line, 
      const std::string what)
  {
    std::stringstream message;
    if (prepend != "") message << "[" << prepend << "]";
    if (thread_id != "") message << "(" << thread_id << ") ";
    message << func << "(" << line << ") : " << what;
    return message.str();
  }
};

// -------------------------------------------------------------
// --- Properties
// -------------------------------------------------------------

string Logger::getName(){ return _logname; };
void  Logger::setName(const string logname){
  _logname = logname;
  closelog();
  openlog(logname.c_str(), LOG_PID | LOG_CONS, LOG_USER);
};

// -------------------------------------------------------------
// --- Public Functions
// -------------------------------------------------------------

void Logger::log(const std::string thread_id, const std::string func, const int line, const std::string what)
{
  std::string  message=Helper::build_message("",thread_id, func, line, what);

  if (enable_log)
    std::cout << message << std::endl;
  if (enable_syslog)
    syslog(LOG_INFO, "%s", message.c_str());
  if (enable_filelog)
    ""; // TODO
};

void Logger::error(const std::string thread_id, const std::string func, const int line, const std::string what)
{
  std::string  message=Helper::build_message("err", thread_id, func, line, what);

  if (enable_log)
    std::cerr << message << std::endl;
  if (enable_syslog)
    syslog(LOG_ERR, "%s", message.c_str());
};

void Logger::debug(const std::string thread_id, const std::string func, const int line, const std::string what)
{
#ifdef E2DEBUG
  std::string  message=Helper::build_message("debug", thread_id, func, line, what);

  if (enable_debug)
    std::cerr << message << std::endl;
  if (enable_syslog)
    syslog(LOG_DEBUG, "%s", message.c_str());
#endif
}

void Logger::trace(const std::string thread_id, const std::string func, const int line, const std::string what="")
{
#ifdef E2DEBUG
  std::string  message=Helper::build_message("trace", thread_id, func, line, what);

  if (enable_debug)
    std::cerr << message << std::endl;
  if (enable_syslog)
    syslog(LOG_DEBUG, "%s", message.c_str());
#endif
}