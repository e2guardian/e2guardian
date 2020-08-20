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

extern bool is_daemonised;

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

#ifdef NOTDEF        // to avoid compiler warning
const std::string Logger::SOURCES[] = {"info", "error", "access", "config", "story", \
                                      "debug", "trace", "debugnet", "debugsb", "chunk", "regexp", \
                                      "icap", "icapc", "clamav", "request"};
const std::string Logger::DESTINATIONS[] = {"none", "stdout", "stderr", "syslog", "file"};
#endif

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
    std::string message;      // overhead of stream no longer required as all params types now known
    if (!prepend.empty())
        ((message = "[") += prepend) += "] ";
    if (!thread_id.empty() && thread_id != "log: ")
      message += thread_id;
#ifdef E2DEBUG
    if (!func.empty()) {
      message += func;
      if (line > 0)
        (message += ":") += std::to_string(line) += " ";
    };
#endif
    message += what;
    return message;
  }

  static  void sendToLogfile(std::ostream *outs, const std::string &message) {
        (*outs) << message << std::endl;
    }

  void sendToLogfile(const std::string &filename, const std::string &message){
    if (filename=="")
      return;
    std::ofstream logfile;
    logfile.open(filename,std::ofstream::out | std::ofstream::app );
    if (!logfile.fail())
      logfile << message << std::endl;
    logfile.close();
  }

  static bool testFile(const std::string &filename){
    bool good;

    if (filename == "") return false;
      std::ofstream logfile(filename,std::ios::out | std::ios::app );
    good = logfile.good();
    logfile.close();
    if (!good) {
      std::cerr << "Failed to open/create logfile: " << filename << " (check ownership and access rights)" << std::endl;
    }
    return good;
  }
};


// -------------------------------------------------------------
// --- static Functions
// -------------------------------------------------------------

LoggerSource Logger::string2source(std::string source){
  for( int i=0; i < static_cast<int>(LoggerSource::__Max_Value); i++)
  {
    if (source == Sources[i]  ) return static_cast<LoggerSource>(i);
  }
  return LoggerSource::info;
}

LoggerDestination Logger::string2dest(std::string destination){
  for( int i=0; i < static_cast<int>(LoggerDestination::__Max_Value); i++)
  {
    if (Destinations[i] == destination) return static_cast<LoggerDestination>(i);
  }
  return LoggerDestination::none;
}

std::string Logger::source2string(LoggerSource source){
  return Sources[static_cast<int>(source)];
}
std::string Logger::dest2string(LoggerDestination dest){
  return Destinations[static_cast<int>(dest)];
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
  source_dests[static_cast<int>(source)].enabled = true;
};
void Logger::enable(const char* source){
  enable(string2source(std::string(source)));
}

void Logger::disable(const LoggerSource source){
  source_dests[static_cast<int>(source)].enabled = false;
};
void Logger::disable(const char* source){
  disable(string2source(std::string(source)));
}

bool Logger::isEnabled(const LoggerSource source) {
   return source_dests[static_cast<int>(source)].enabled;
};
bool Logger::isEnabled(const char* source){
  return isEnabled(string2source(std::string(source)));
}

void Logger::setLogOutput(const LoggerSource source, const LoggerDestination destination, const std::string filename,
                          const bool alsoEnable){
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
  source_rec *srec = &source_dests[static_cast<int>(source)];
  LoggerDestination destination = srec->destination;
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
      if (source == LoggerSource::error) {
        loglevel = LOG_ERR;
        if (!is_daemonised )
          std::cerr << message << std::endl;   // show to console as well as syslog when not daemonised
      } else if (source >= LoggerSource::debug)
        loglevel = LOG_DEBUG;
      else
        loglevel = LOG_INFO;
      syslog(srec->syslog_flag, "%s", message.c_str());
      break;
    case LoggerDestination::file:
      //  std::cerr << "Acesss filename = " << srec->filename << std::endl;
        if(srec->outs == nullptr)
            std::cerr << "log outs is nullptr";
        else
            Helper::sendToLogfile(srec->outs, message);
      break;
      case LoggerDestination::__Max_Value:
          break;
  }

}
void Logger::setDestination(const LoggerSource source, const LoggerDestination destination){
  source_dests[static_cast<int>(source)].destination = destination;
}
void Logger::setFilename(const LoggerSource source, const std::string filename){
  std::string name;

  source_dests[static_cast<int>(source)].filename = "";  // clear current entry

    if (!filename.empty()) {
        if (filename.front() == '/')    // absolute path
            name = filename;
        else        // relative to __LOGLOCATION
            name = std::string(__LOGLOCATION) + filename;

        std::ofstream *file_stream = new std::ofstream(name, std::ios::out | std::ios::app);
        if (file_stream->fail()) {
            std::cerr << "Failed to open/create logfile: " << filename << " (check ownership and access rights)" << std::endl;
            delete file_stream;
            return;
        }
        source_dests[static_cast<int>(source)].filename = name;
        source_dests[static_cast<int>(source)].outs = file_stream;
    }
}

