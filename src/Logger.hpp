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

using namespace std::string_literals;

class Logger
{
  public:
  Logger();   // constructor
  Logger(const char* logname);
  ~Logger();  // destructor

  bool enable_conlog;
  bool enable_syslog;
  bool enable_filelog;

  bool enable_debug;
  bool enable_trace;
  bool enable_story;

  void setName(const std::string logname); // for syslog
  void setLogFile(const std::string filename);
  void setDockerMode();

  void info(const std::string thread_id, const std::string func, const int line, const std::string what);
  void error(const std::string thread_id, const std::string func, const int line, const std::string what);
  void debug(const std::string thread_id, const std::string func, const int line, const std::string what);
  void trace(const std::string thread_id, const std::string func, const int line, const std::string what);
  void story(const std::string thread_id, const std::string what);

  private:
  bool _dockermode;
  std::string _logname;
  std::string _filename;
  struct Helper;

  void sendMessage(int loglevel, const std::string message);
};

extern Logger* __logger;

#define logger_info(...)  __logger->info(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_error(...) __logger->error(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_debug(...) __logger->debug(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_trace(...) __logger->trace(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_story(...) __logger->story(thread_id,  __VA_ARGS__)

#endif
