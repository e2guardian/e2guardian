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
//#include <sstream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <atomic>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

// only C++14 : using namespace std::string_literals;

// FileRec: handling open/write/rotate/close of files
class FileRec {
public:
    FileRec(std::string filename, bool unbuffered);   //constructor
    ~FileRec();                                       //destructor

    std::string filename;
    int link_count = 0;

    bool open();
    bool write(std::string &msg);
    bool rotate();
    bool flush();
    bool close();

private:
    FILE *file_stream;
    bool unbuffered = false;
};


enum class LoggerSource {
    none,
    // used in production:
            info, error, warning, accesslog, requestlog, storytrace, dstatslog,
    // only usable when compiled with DEBUG_LOW:
            debug, trace, network, story, regexp, config, content,
    // only usable when compiled with DEBUG_HIGH:
            icap, avscan, auth, dwload, proxy, thttps,
    __Max_Value
};

enum class LoggerDestination {
  none, stdout, stderr, syslog, file,
  __Max_Value
};

class Logger {
public:
    Logger();   // constructor
    ~Logger();  // destructor

    void setSyslogName(const std::string logname);
    void setDockerMode();

    // enable/disable Logging Sources
    void enable(const LoggerSource source);
    void enable(const char *source);

    void disable(const LoggerSource source);
    void disable(const char *source);

    bool isEnabled(const LoggerSource source);
    bool isEnabled(const char *source);

    bool rotate(const LoggerSource source);
    bool flush(const LoggerSource source);

    bool setLogOutput(const LoggerSource source, const LoggerDestination destination, const std::string filename = "",
                      const bool alsoEnable = true);

    void log(const LoggerSource source, std::string message);

    void log(const LoggerSource source, const std::string func, const std::string file, const int line, std::string message);

    // Conversion Enum <-> string
    std::vector <std::string> Sources = {"none",
                                         "info", "error", "warning", "accesslog", "requestlog", "storytrace", "dstatslog",
            // only usable when compiled with DEBUG_LOW:
                                         "debug", "trace", "network", "story", "regexp", "config", "content",
            // only usable when compiled with DEBUG_HIGH:
                                         "icap", "avscan", "auth", "dwload", "proxy", "thttps"};

    std::vector <std::string> Destinations = {"none", "stdout", "stderr", "syslog", "file"};

    std::vector <LoggerSource> working_messages = {
            LoggerSource::info,
            LoggerSource::error,
            LoggerSource::warning,
    };

    std::vector <LoggerSource> working_logs = {
            LoggerSource::accesslog,
            LoggerSource::requestlog,
            LoggerSource::dstatslog,
    };

    std::vector <LoggerSource> debug_messages = {
            LoggerSource::trace,
            LoggerSource::config,
            LoggerSource::debug,
            LoggerSource::avscan,
            LoggerSource::icap,
            LoggerSource::network,
            LoggerSource::regexp,
            LoggerSource::story,
            LoggerSource::auth,
            LoggerSource::dwload,
            LoggerSource::proxy,
            LoggerSource::thttps,
            LoggerSource::content,
    };


    LoggerSource string2source(std::string source);

    LoggerDestination string2dest(std::string destination);

    std::string source2string(LoggerSource source);

    std::string dest2string(LoggerDestination dest);

    void setFormat(const LoggerSource source, bool no_format, bool show_tag = false, bool show_func = false,
                   bool func_last = true, bool show_thread_id = true);

    void setMultiFormat(std::vector <LoggerSource> *source_list, bool no_format, bool show_tag, bool show_func,
                        bool func_last, bool show_thread_id = true);

    // Variable Args
    template<typename T>
    void cat_vars(std::stringstream &mess, T e) {
        mess << e;
    }

    template<typename T, typename... Args>
    void cat_vars(std::stringstream &mess, T e, Args... args) {
        mess << e;
        cat_vars(mess, args...);
    }

    template<typename... Args>
    std::string cat_all_vars(Args... args) {
        std::stringstream mess;
        cat_vars(mess, args...);
        return mess.str();
    }

    template<typename... Args>
    void vlog(const LoggerSource source, const std::string func, const std::string file, const int line, Args... args) {
        log(source, func, file, line, cat_all_vars(args...));

    };


private:

    std::string _syslogname;

    std::vector <FileRec*> Files;

    struct SourceRec {
        bool enabled = false;
        LoggerDestination destination = LoggerDestination::none;
        FileRec *fileRec = nullptr;
        int syslog_flag = LOG_INFO;
        bool show_funct_line = false;
        bool funct_line_last = true;
        bool show_source_category = false;
        bool show_thread_id = true;
        bool no_format = false;
    };

    SourceRec sourceRecs[static_cast<int>(LoggerSource::__Max_Value)];


    FileRec *findFileRec(std::string filename);

    FileRec *addFile(std::string filename, bool unbuffered);

    void rmFileLink(FileRec *fileRec);

    void deleteFileEntry(std::string filename);


    // arrays below replaced with array of source_rec
    //bool _enabled[static_cast<int>(LoggerSource::__Max_Value)];
    //LoggerDestination _destination[static_cast<int>(LoggerSource::__Max_Value)];
    //std::string _filename[static_cast<int>(LoggerSource::__Max_Value)];

    struct Helper;

    void sendMessage(const LoggerSource source, std::string &message);

    void setDestination(const LoggerSource source, const LoggerDestination destination);

    bool setFilename(const LoggerSource source, const std::string filename);

    bool setSyslogLevel(const LoggerSource source, const std::string level);


};

extern thread_local std::string thread_id;
extern std::atomic<bool> g_is_starting;

extern Logger e2logger;

#define E2LOGGER_info(...)  \
  if (e2logger.isEnabled(LoggerSource::info)) \
     e2logger.vlog(LoggerSource::info,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#define E2LOGGER_warn(...)  \
  if (e2logger.isEnabled(LoggerSource::warning)) \
     e2logger.vlog(LoggerSource::warning,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#define E2LOGGER_error(...) \
  if (e2logger.isEnabled(LoggerSource::error)) \
     e2logger.vlog(LoggerSource::error,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#define E2LOGGER_accesslog(STR)  \
  if (e2logger.isEnabled(LoggerSource::accesslog)) \
     e2logger.log(LoggerSource::accesslog, STR)

#define E2LOGGER_requestlog(STR) \
    if (e2logger.isEnabled(LoggerSource::requestlog)) \
      e2logger.log(LoggerSource::requestlog, STR)

#define E2LOGGER_dstatslog(STR) \
    if (e2logger.isEnabled(LoggerSource::dstatslog)) \
      e2logger.log(LoggerSource::dstatslog, STR)

#define E2LOGGER_storytrace(...) \
  if (e2logger.isEnabled(LoggerSource::storytrace)) \
    e2logger.vlog(LoggerSource::storytrace, (const std::string) "", (const std::string) "", (int) 0,  __VA_ARGS__)



#ifdef DEBUG_HIGH
  #define DEBUG_icap(...) \
     if (e2logger.isEnabled(LoggerSource::icap)) \
       e2logger.vlog(LoggerSource::icap,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_avscan(...) \
    if (e2logger.isEnabled(LoggerSource::avscan)) \
      e2logger.vlog(LoggerSource::avscan,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_auth(...) \
    if (e2logger.isEnabled(LoggerSource::auth)) \
      e2logger.vlog(LoggerSource::auth,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_dwload(...) \
    if (e2logger.isEnabled(LoggerSource::dwload)) \
      e2logger.vlog(LoggerSource::dwload,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_proxy(...) \
    if (e2logger.isEnabled(LoggerSource::proxy)) \
      e2logger.vlog(LoggerSource::proxy,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_thttps(...) \
    if (e2logger.isEnabled(LoggerSource::thttps)) \
      e2logger.vlog(LoggerSource::thttps,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#else
  #define DEBUG_icap(...)
  #define DEBUG_avscan(...)
  #define DEBUG_auth(...)
  #define DEBUG_dwload(...)
  #define DEBUG_proxy(...)
  #define DEBUG_thttps(...)
#endif


#ifdef DEBUG_LOW

#define DEBUG_debug(...) \
    if (e2logger.isEnabled(LoggerSource::debug)) \
      e2logger.vlog(LoggerSource::debug,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_trace(...) \
    if (e2logger.isEnabled(LoggerSource::trace)) \
      e2logger.vlog(LoggerSource::trace,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_network(...) \
    if (e2logger.isEnabled(LoggerSource::network)) \
      e2logger.vlog(LoggerSource::network,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_regexp(...) \
    if (e2logger.isEnabled(LoggerSource::regexp)) \
      e2logger.vlog(LoggerSource::regexp,  __func__, __FILE__,__LINE__, __VA_ARGS__)

  #define DEBUG_story(...) \
    if (e2logger.isEnabled(LoggerSource::story)) \
      e2logger.vlog(LoggerSource::story,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#define DEBUG_config(...) \
  if (e2logger.isEnabled(LoggerSource::config)) \
     e2logger.vlog(LoggerSource::config,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#define DEBUG_content(...) \
  if (e2logger.isEnabled(LoggerSource::content)) \
     e2logger.vlog(LoggerSource::content,  __func__, __FILE__,__LINE__, __VA_ARGS__)

#else
  #define DEBUG_debug(...)
  #define DEBUG_trace(...)
  #define DEBUG_network(...)
  #define DEBUG_regexp(...)
  #define DEBUG_story(...)
  #define DEBUG_config(...)
  #define DEBUG_content(...)
  #define DEBUG_low_icap(...)
  #define DEBUG_low_avscan(...)
  #define DEBUG_low_auth(...)
  #define DEBUG_low_dwload(...)
  #define DEBUG_low_proxy(...)
  #define DEBUG_low_thttps(...)
#endif


#endif
