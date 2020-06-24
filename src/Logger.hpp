
#ifndef __HPP_LOGGING
#define __HPP_LOGGING

class Logger
{
  public:
  Logger();   // constructor
  Logger(const char* logname);
  ~Logger();  // destructor

  bool enable_log;
  bool enable_syslog;
  bool enable_filelog;
  bool enable_debug;
  bool enable_trace;

  std::string getName();
  void  setName(const std::string logname);

  void log  (const std::string thread_id, const std::string func, const int line, const std::string what);
  void error(const std::string thread_id, const std::string func, const int line, const std::string what);
  void debug(const std::string thread_id, const std::string func, const int line, const std::string what);
  void trace(const std::string thread_id, const std::string func, const int line, const std::string what);

  private:
  std::string _logname;
  struct Helper;
};


#define logger_log(...)   __logger->log(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_error(...) __logger->error(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_debug(...) __logger->debug(thread_id, __func__, __LINE__, __VA_ARGS__)
#define logger_trace(...) __logger->trace(thread_id, __func__, __LINE__, __VA_ARGS__)

#endif
