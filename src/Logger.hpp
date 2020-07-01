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

#include <sstream>

// only C++14 : using namespace std::string_literals;

enum class LoggerSource {
  // used in production:
  info, error, config, story, icap, icapc, clamav, thhtps,
  // only usable when compiled with E2DEBUG:
  debug, trace, debugnet, debugsb, debugchunk, debugregexp,
  __MAX_VALUE
};

enum class LoggerDestination {
  none, stdout, stderr, syslog, file,
  __MAX_VALUE
};

class Logger
{
  public:
  Logger();   // constructor
  ~Logger();  // destructor

  void setSyslogName(const std::string logname);

  // enable/disable Logging Sources
  void enable(const LoggerSource source);
  void disable(const LoggerSource source);
  bool isEnabled(const LoggerSource source);

  void setLogOutput(const LoggerSource source, const LoggerDestination destination, const std::string filename="");

  void setDockerMode();

  void log(const LoggerSource source, const std::string func, const int line, const std::string message );

  // Conversion Enum <-> string
  static const std::string SOURCES[static_cast<int>(LoggerSource::__MAX_VALUE)];
  static const std::string DESTINATIONS[static_cast<int>(LoggerDestination::__MAX_VALUE)];

  static LoggerSource string2source(std::string source);
  static LoggerDestination string2dest(std::string destination);

  static std::string source2string(LoggerSource source);
  static std::string dest2string(LoggerDestination dest);

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
  std::string _logname;

  bool _enabled[static_cast<int>(LoggerSource::__MAX_VALUE)];
  LoggerDestination _destination[static_cast<int>(LoggerSource::__MAX_VALUE)];
  std::string _filename[static_cast<int>(LoggerSource::__MAX_VALUE)];

  struct Helper;

  void sendMessage(const LoggerSource source, const std::string message);
};

extern thread_local std::string thread_id;

extern Logger __logger;

#define logger_info(...)  \
  if (__logger.isEnabled(LoggerSource::info)) \
     __logger.vlog(LoggerSource::info,  __func__, __LINE__, __VA_ARGS__)
#define logger_error(...) \
  if (__logger.isEnabled(LoggerSource::error)) \
     __logger.vlog(LoggerSource::error,  __func__, __LINE__, __VA_ARGS__)
#define logger_config(...) \
  if (__logger.isEnabled(LoggerSource::config)) \
     __logger.vlog(LoggerSource::config,  __func__, __LINE__, __VA_ARGS__)
#define logger_story(...) \
  if (__logger.isEnabled(LoggerSource::story)) \
    __logger.vlog(LoggerSource::story, "", 0,  __VA_ARGS__)


#ifdef E2DEBUG
  #define logger_debug(...) \
    if (__logger.isEnabled(LoggerSource::debug)) \
      __logger.vlog(LoggerSource::debug,  __func__, __LINE__, __VA_ARGS__)
  #define logger_trace(...) \
    if (__logger.isEnabled(LoggerSource::trace)) \
      __logger.vlog(LoggerSource::trace,  __func__, __LINE__, __VA_ARGS__)
  #define logger_debugnet(...) \
    if (__logger.isEnabled(LoggerSource::debugnet)) \
      __logger.vlog(LoggerSource::debugnet,  __func__, __LINE__, __VA_ARGS__)
  #define logger_debugregexp(...) \
    if (__logger.isEnabled(LoggerSource::debugregexp)) \
      __logger.vlog(LoggerSource::debugregexp,  __func__, __LINE__, __VA_ARGS__)
  #define logger_debugsb(...) \
    if (__logger.isEnabled(LoggerSource::debugsb)) \
      __logger.vlog(LoggerSource::debugsb,  __func__, __LINE__, __VA_ARGS__)

#else
  #define logger_debug(...)
  #define logger_trace(...)
  #define logger_debugnet(...)
  #define logger_debugregexp(...)
  #define logger_debugsb(...)
#endif


#endif
