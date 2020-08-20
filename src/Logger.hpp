// Logger class - for central logging to console/syslog/file
//
// Author  : Klaus-Dieter Gundermann
// Created : 24.06.2020
//
// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LOGGING
#define __HPP_LOGGING

#include <vector>
#include <sstream>
#include <syslog.h>

// only C++14 : using namespace std::string_literals;

enum class LoggerSource {
  // used in production:
  info, error, access, config, story, 
  // only usable when compiled with E2DEBUG:
  debug, trace, debugnet, debugsb, debugchunk, debugregexp,
  debugicap, debugicapc, debugclamav, debugrequest,
  __Max_Value
};

enum class LoggerDestination {
  none, stdout, stderr, syslog, file,
  __Max_Value
};

class Logger
{
  public:
  Logger();   // constructor
  ~Logger();  // destructor

  void setSyslogName(const std::string logname);

  // enable/disable Logging Sources
  void enable(const LoggerSource source);
  void enable(const char* source);

  void disable(const LoggerSource source);
  void disable(const char* source);
  
  bool isEnabled(const LoggerSource source);
  bool isEnabled(const char* source);

  void setLogOutput(const LoggerSource source, const LoggerDestination destination, const std::string filename="", const bool alsoEnable = true);

  void setDockerMode();

  void log(const LoggerSource source, const std::string func, const int line, const std::string message );

  // Conversion Enum <-> string
  std::string Sources[15] = {"info", "error", "access", "config", "story", \
                                      "debug", "trace", "debugnet", "debugsb", "chunk", "regexp", \
                                      "icap", "icapc", "clamav", "request"};
  std::string Destinations[5] = {"none", "stdout", "stderr", "syslog", "file"};

  //static const std::string SOURCES[static_cast<int>(LoggerSource::__Max_Value)];
  //static const std::string DESTINATIONS[static_cast<int>(LoggerDestination::__Max_Value)];

  LoggerSource string2source(std::string source);
  LoggerDestination string2dest(std::string destination);

  std::string source2string(LoggerSource source);
  std::string dest2string(LoggerDestination dest);

  // Variable Args
  template<typename T>  void cat_vars(std::stringstream &mess, T e) {
      mess << e;
  }
  template<typename T, typename... Args>  void cat_vars(std::stringstream &mess, T e, Args... args) {
      mess << e;
      cat_vars(mess, args...);
  }
  template<typename... Args> std::string cat_all_vars(Args... args) {
      std::stringstream mess;
      cat_vars(mess, args...);
      return mess.str();
  }
  template<typename... Args>  void vlog(const LoggerSource source, const std::string func, const int line, Args... args) {
      log(source, func, line, cat_all_vars(args...));
  };

  private:

    struct source_rec {
        bool enabled = false;
        LoggerDestination destination = LoggerDestination::none;
        std::string filename;
        std::ostream *outs = nullptr;
        int syslog_flag = LOG_INFO;
        bool show_funct_line = false;
        bool funct_line_last = true;
        bool show_source_category = false;
        bool show_thread_id = true;
    };

    source_rec source_dests[static_cast<int>(LoggerSource::__Max_Value)];

  std::string _logname;

  // arrays below replaced with array of source_rec
  //bool _enabled[static_cast<int>(LoggerSource::__Max_Value)];
  //LoggerDestination _destination[static_cast<int>(LoggerSource::__Max_Value)];
  //std::string _filename[static_cast<int>(LoggerSource::__Max_Value)];

    std::vector<LoggerSource> working_messages = {
            LoggerSource::info,
            LoggerSource::error,
            LoggerSource::story,
    };

    std::vector<LoggerSource> working_logs = {
            LoggerSource::access,
            LoggerSource::debugrequest,
    };

    std::vector<LoggerSource> debug_messages = {
            LoggerSource::trace,
            LoggerSource::debug,
            LoggerSource::debugchunk,
            LoggerSource::debugclamav,
            LoggerSource::debugicap,
            LoggerSource::debugicapc,
            LoggerSource::debugnet,
            LoggerSource::debugregexp,
            LoggerSource::debugsb,
    };

  struct Helper;

  void sendMessage(const LoggerSource source, const std::string message);
  void setDestination(const LoggerSource source, const LoggerDestination destination);
  void setFilename(const LoggerSource source, const std::string filename);
};

extern thread_local std::string thread_id;

extern Logger e2logger;

#define E2LOGGER_info(...)  \
  if (e2logger.isEnabled(LoggerSource::info)) \
     e2logger.vlog(LoggerSource::info,  __func__, __LINE__, __VA_ARGS__)
#define E2LOGGER_error(...) \
  if (e2logger.isEnabled(LoggerSource::error)) \
     e2logger.vlog(LoggerSource::error,  __func__, __LINE__, __VA_ARGS__)

#define E2LOGGER_access(STR)  \
  if (e2logger.isEnabled(LoggerSource::access)) \
     e2logger.vlog(LoggerSource::access,  __func__, __LINE__, STR)
#define E2LOGGER_debugrequest(...) \
    if (e2logger.isEnabled(LoggerSource::debugrequest)) \
      e2logger.vlog(LoggerSource::debugrequest,  __func__, __LINE__, __VA_ARGS__)

#define E2LOGGER_config(...) \
  if (e2logger.isEnabled(LoggerSource::config)) \
     e2logger.vlog(LoggerSource::config,  __func__, __LINE__, __VA_ARGS__)
#define E2LOGGER_story(...) \
  if (e2logger.isEnabled(LoggerSource::story)) \
    e2logger.vlog(LoggerSource::story, "", 0,  __VA_ARGS__)


#ifdef E2DEBUG
  #define E2LOGGER_debug(...) \
    if (e2logger.isEnabled(LoggerSource::debug)) \
      e2logger.vlog(LoggerSource::debug,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_trace(...) \
    if (e2logger.isEnabled(LoggerSource::trace)) \
      e2logger.vlog(LoggerSource::trace,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_debugnet(...) \
    if (e2logger.isEnabled(LoggerSource::debugnet)) \
      e2logger.vlog(LoggerSource::debugnet,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_debugregexp(...) \
    if (e2logger.isEnabled(LoggerSource::debugregexp)) \
      e2logger.vlog(LoggerSource::debugregexp,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_debugsb(...) \
    if (e2logger.isEnabled(LoggerSource::debugsb)) \
      e2logger.vlog(LoggerSource::debugsb,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_debugicap(...) \
     if (e2logger.isEnabled(LoggerSource::debugicap)) \
       e2logger.vlog(LoggerSource::debugicap,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_debugicapc(...) \
    if (e2logger.isEnabled(LoggerSource::debugicapc)) \
      e2logger.vlog(LoggerSource::debugicapc,  __func__, __LINE__, __VA_ARGS__)
  #define E2LOGGER_debugclamav(...) \
    if (e2logger.isEnabled(LoggerSource::debugclamav)) \
      e2logger.vlog(LoggerSource::debugclamav,  __func__, __LINE__, __VA_ARGS__)

#else
  #define E2LOGGER_debug(...)
  #define E2LOGGER_trace(...)
  #define E2LOGGER_debugnet(...)
  #define E2LOGGER_debugregexp(...)
  #define E2LOGGER_debugsb(...)
  #define E2LOGGER_debugicap(...)
  #define E2LOGGER_debugicapc(...)
  #define E2LOGGER_debugclamav(...)
  #define E2LOGGER_debugrequest(...)
#endif


#endif
