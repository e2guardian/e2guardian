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

// -------------------------------------------------------------
// --- Global Logger
// -------------------------------------------------------------

Logger e2logger;

// -------------------------------------------------------------
// --- Constructor
// -------------------------------------------------------------
Logger::Logger() {
  setSyslogName("Logger");

  setLogOutput(LoggerSource::info,  LoggerDestination::stdout);
  setLogOutput(LoggerSource::error, LoggerDestination::stderr);
  setLogOutput(LoggerSource::access, LoggerDestination::file, "access.log");

  setLogOutput(LoggerSource::debug, LoggerDestination::stdout, "", false);
  setLogOutput(LoggerSource::trace, LoggerDestination::stdout, "", false);
}

Logger::~Logger() {
  closelog();
}

const std::string Logger::SOURCES[] = {"info", "error", "access", "config", "story", \
                                      "debug", "trace", "debugnet", "debugsb", "chunk", "regexp", \
                                      "icap", "icapc", "clamav", "request"};
const std::string Logger::DESTINATIONS[] = {"none", "stdout", "stderr", "syslog", "file"};

// -------------------------------------------------------------
// --- Helper
// -------------------------------------------------------------

struct Logger::Helper
{
  static std::string build_message(
      const std::string prepend,      
      const std::string func, 
      const int line, 
      const std::string what)
  {
    std::stringstream message;
    if (prepend != "") 
      message << "[" << prepend << "] ";
    if (thread_id != "" && thread_id != "log: ") 
      message << "(" << thread_id << ") ";
#ifdef E2DEBUG
    if (func != "") {
      message << " " << func;
      if (line > 0)
        message << ":" << line << " ";
    };
#endif
    message << what;
    return message.str();
  }

  static void sendToLogfile(const std::string &filename, const std::string &message){
    if (filename=="")
      return;
    std::ofstream logfile;
    logfile.open(filename,std::ofstream::out | std::ofstream::app );
    if (!logfile.fail())
      logfile << message << std::endl;
    logfile.close();
  }

  static bool testFile(const std::string &filename){
    std::ofstream logfile;
    bool fail;

    if (filename == "") return false;
    logfile.open(filename,std::ofstream::out | std::ofstream::app );
    fail = logfile.fail();
    logfile.close();
    if (fail) {
      std::cerr << "Failed to open/create logfile: " << filename << " (check ownership and access rights)" << std::endl;
    }
    return fail;
  }
};

// -------------------------------------------------------------
// --- static Functions
// -------------------------------------------------------------

LoggerSource Logger::string2source(std::string source){
  for( int i=0; i < static_cast<int>(LoggerSource::__MAX_VALUE); i++)
  {
    if (Logger::SOURCES[i] == source) return static_cast<LoggerSource>(i);
  }
  return LoggerSource::info;
}
LoggerDestination Logger::string2dest(std::string destination){
  for( int i=0; i < static_cast<int>(LoggerDestination::__MAX_VALUE); i++)
  {
    if (Logger::DESTINATIONS[i] == destination) return static_cast<LoggerDestination>(i);
  }
  return LoggerDestination::none;
}

std::string Logger::source2string(LoggerSource source){
  return Logger::SOURCES[static_cast<int>(source)];
}
std::string Logger::dest2string(LoggerDestination dest){
  return Logger::DESTINATIONS[static_cast<int>(dest)];
}


// -------------------------------------------------------------
// --- Properties
// -------------------------------------------------------------

void  Logger::setSyslogName(const std::string logname){
  _logname = logname;
  closelog();
  openlog(logname.c_str(), LOG_PID | LOG_CONS, LOG_USER);
};

void Logger::enable(const LoggerSource source){
  _enabled[static_cast<int>(source)] = true;
};
void Logger::enable(const char* source){
  enable(string2source(std::string(source)));
}

void Logger::disable(const LoggerSource source){
  _enabled[static_cast<int>(source)] = false;
};
void Logger::disable(const char* source){
  disable(string2source(std::string(source)));
}

bool Logger::isEnabled(const LoggerSource source){
  return _enabled[static_cast<int>(source)];
};
bool Logger::isEnabled(const char* source){
  return isEnabled(string2source(std::string(source)));
}

void Logger::setLogOutput(const LoggerSource source, const LoggerDestination destination, const std::string filename, const bool alsoEnable){
  setDestination(source, destination);
  setFilename(source, filename);

  if (destination == LoggerDestination::none)
    disable(source);
  else if (alsoEnable)  
    enable(source);  
}  

void Logger::setDockerMode(){
  // docker stdout/stderr are not in sync
  // so for debugging send everything to stderr (unbuffered)
  setDestination(LoggerSource::info, LoggerDestination::stderr);
  setDestination(LoggerSource::error, LoggerDestination::stderr);
  setDestination(LoggerSource::access, LoggerDestination::stderr);
  setDestination(LoggerSource::debug, LoggerDestination::stderr);
  setDestination(LoggerSource::trace, LoggerDestination::stderr);
}


// -------------------------------------------------------------
// --- Public Functions
// -------------------------------------------------------------

void Logger::log(const LoggerSource source, const std::string func, const int line, const std::string message )
{
  std::string tag;
  std::string msg;
  if (source > LoggerSource::access) {
    tag=source2string(source);
    msg=Helper::build_message(tag, func, line, message);
  } else {
    // no tags,func,line for: info,error,access
    msg=Helper::build_message("", "", 0, message);
  }
  sendMessage(source, msg);
};


// -------------------------------------------------------------
// --- Private Functions
// -------------------------------------------------------------

void Logger::sendMessage(const LoggerSource source, const std::string message){
  LoggerDestination destination = _destination[static_cast<int>(source)];
  int loglevel;

  switch (destination) {
    case LoggerDestination::none: 
      break;
    case LoggerDestination::stdout:
      std::cout << message << std::endl;
      break;
    case LoggerDestination::stderr:
      std::cerr << message << std::endl;
      break;
    case LoggerDestination::syslog:
      if (source == LoggerSource::error)
        loglevel = LOG_ERR;
      else if (source >= LoggerSource::debug)
        loglevel = LOG_DEBUG;
      else
        loglevel = LOG_INFO;
      syslog(loglevel, "%s", message.c_str());
      break;
    case LoggerDestination::file:
      Helper::sendToLogfile(_filename[static_cast<int>(source)], message);
      break;
      case LoggerDestination::__MAX_VALUE:
          break;
  }

}
void Logger::setDestination(const LoggerSource source, const LoggerDestination destination){
  _destination[static_cast<int>(source)] = destination;
}
void Logger::setFilename(const LoggerSource source, const std::string filename){
  std::string name;

  if (filename.front() == '/')    // absolute path
    name = filename;
  else if (filename != "")       // relative to __LOGLOCATION
    name = std::string(__LOGLOCATION) + filename;
  else
    name = "";

  if (Helper::testFile(name))
    _filename[static_cast<int>(source)] = name;
  else
    _filename[static_cast<int>(source)] = "";
}

