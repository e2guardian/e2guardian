// Logger class - for central logging to console/syslog/file
//
// Author  : Klaus-Dieter Gundermann
// Created : 24.06.2020
//
// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
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
    if (prepend != "") message << "[" << prepend << "] ";
    if (thread_id != "") message << "(" << thread_id << ") ";
    if (func != "") {
      message << func;
      if (line > 0)
        message << ":" << line << " ";
    };
    message << what;
    return message.str();
  }

  static void sendToLogfile(const std::string filename, const std::string message){
    if (filename=="")
      return;
    ofstream logfile;
    logfile.open(filename);
    logfile << message;
    logfile.close();
  }
};

// -------------------------------------------------------------
// --- Properties
// -------------------------------------------------------------

// string Logger::getName(){ return _logname; };
void  Logger::setName(const string logname){
  _logname = logname;
  closelog();
  openlog(logname.c_str(), LOG_PID | LOG_CONS, LOG_USER);
};

void  Logger::setLogFile(const string filename){
  _filename = filename;
  enable_filelog = true;
}  

void Logger::setDockerMode(){
  enable_conlog = true;
  enable_syslog = false;
  _dockermode = true;
}


// -------------------------------------------------------------
// --- Public Functions
// -------------------------------------------------------------

void Logger::info(const std::string thread_id, const std::string func, const int line, const std::string what)
{
  std::string  message=Helper::build_message("",thread_id, func, line, what);
  sendMessage(_LOG_INFO, message);
};

void Logger::error(const std::string thread_id, const std::string func, const int line, const std::string what)
{
  std::string  message=Helper::build_message("err", thread_id, func, line, what);
  sendMessage(_LOG_ERR, message);
};

void Logger::debug(const std::string thread_id, const std::string func, const int line, const std::string what)
{
#ifdef E2DEBUG
  std::string  message=Helper::build_message("debug", thread_id, func, line, what);
  if (enable_debug)
    sendMessage(_LOG_DEBUG, message);
#endif
}

void Logger::trace(const std::string thread_id, const std::string func, const int line, const std::string what="")
{
#ifdef E2DEBUG
  std::string  message=Helper::build_message("trace", thread_id, func, line, what);
  if (enable_debug)
    sendMessage(_LOG_DEBUG, message);
#endif
}

void Logger::story(const std::string thread_id, const std::string what="")
{
  if (enable_story) {
    std::string  message=Helper::build_message("story", thread_id, "", 0, what);
    sendMessage(_LOG_INFO, message);
  }
}


// -------------------------------------------------------------
// --- Private Functions
// -------------------------------------------------------------

void Logger::sendMessage(int loglevel, const std::string message){
    if (enable_conlog)
      if (loglevel > LOG_ERR) {
        std::cout << message << std::endl;
      }
      else if (_dockermode && enable_debug) {
        // docker stdout/stderr are not in sync
        // so for debugging send it to std:cout
        std::cout << message << std::endl;
      }
      else {
        std::cerr << message << std::endl;
      };

    if (enable_syslog)
      syslog(loglevel, "%s", message.c_str());

    if (enable_filelog)
      Helper::sendToLogfile(_filename, message);
  }

// -------------------------------------------------------------
// --- Global Logger
// -------------------------------------------------------------

Logger* __logger;
