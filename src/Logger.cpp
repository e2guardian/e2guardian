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
#include <cstdio>
#include "Logger.hpp"

// -------------------------------------------------------------
// --- Global Logger
// -------------------------------------------------------------

Logger e2logger;

// -------------------------------------------------------------
// --- Constructor
// -------------------------------------------------------------
Logger::Logger() {
    setSyslogName(PACKAGE);
    // set up default output formats
    // bools are no_format, show_tag, show_func, func_last
    setMultiFormat(&working_logs,true,false,false,false,false);
    setMultiFormat(&working_messages,false,false,false,false, true);
    setMultiFormat(&debug_messages,false,false,true, true, true);   // this can be overwritten by the debuglevel option

    setFormat(LoggerSource::storytrace,false,false,false,false,true);

    setLogOutput(LoggerSource::info, LoggerDestination::syslog, "LOG_INFO");
    setLogOutput(LoggerSource::error, LoggerDestination::syslog, "LOG_ERR");
    setLogOutput(LoggerSource::warning, LoggerDestination::syslog, "LOG_WARNING");

    setLogOutput(LoggerSource::storytrace, LoggerDestination::syslog,"LOG_INFO", false);

    setLogOutput(LoggerSource::debug, LoggerDestination::stdout, "", false);
    setLogOutput(LoggerSource::trace, LoggerDestination::stdout, "", false);
}

Logger::~Logger() {
    closelog();
    if (!Files.empty()) {
        for (std::vector<FileRec *>::iterator i = Files.begin(); i != Files.end(); i++) {
            if (*i != nullptr) {
                (*i)->close();
                delete *i;
            }
        }
    }
}

// -------------------------------------------------------------
// --- Helper
// -------------------------------------------------------------

struct Logger::Helper {
    static std::string build_message(
            SourceRec *rec,
            std::string &prepend,
            const std::string &func,
            const std::string &file,
            const int &line,
            std::string what) {

        std::string message;
        if (rec->show_source_category) {
            ((message = "(") += prepend) += ") ";
        }
        if (rec->show_thread_id)
            message += thread_id;
        if (rec->show_funct_line && !rec->funct_line_last) {
            message.append(func).append("():").append(file).append(":").append(std::to_string(line)).append(" ");
        }
        message += what;
        if (rec->show_funct_line && rec->funct_line_last) {
            message.append(" ").append(func).append("():").append(file).append(":").append(std::to_string(line));
        }
        return message;
    }
};

// -------------------------------------------------------------
// --- FileRec 
// -------------------------------------------------------------

FileRec::FileRec(std::string filename, bool unbuffered) {
    this->filename = filename;
    this->unbuffered = unbuffered;
    this->link_count = 1;
}    
FileRec::~FileRec() {
    close();
}       

bool FileRec::open() {
    mode_t old_umask = umask(S_IWGRP | S_IWOTH);
    file_stream = fopen(filename.c_str(), "a");
    umask(old_umask);
    if (!file_stream) {
        std::cerr << "Failed to open/create logfile: " << filename << " (check ownership and access rights)"
                    << std::endl;
        return false;
    }
    if (unbuffered)
        setvbuf(file_stream, NULL, _IONBF, 0);
    return true;
}

bool FileRec::write(std::string &msg) {
    if (file_stream == nullptr) {
        std::cerr << "file_stream is null" << std::endl;
        return false;
    } else {
        return (fprintf(file_stream, "%s\n", msg.c_str()) >= 0);
    }
}
bool FileRec::flush() {
    if(file_stream == nullptr)
        return false;
    fflush(file_stream);
    return true;
}

bool FileRec::rotate() {   // this must only be called by a single thread which controls all output to this file
    if(file_stream == nullptr)
        return false;

    flush();
    close();
    std::string rfn = filename;
    rfn += ".old";
    if (link(filename.c_str(), rfn.c_str()) == 0) {
        unlink(filename.c_str());
        return open();
    }
    return false;
}

bool FileRec::close() {
    if(file_stream == nullptr)
        return false;
    int rc = fclose(file_stream);
    file_stream = nullptr;
    return (rc == 0);
}    


// -------------------------------------------------------------
// --- static Functions
// -------------------------------------------------------------

LoggerSource Logger::string2source(std::string source) {
    for (int i = 0; i < static_cast<int>(LoggerSource::__Max_Value); i++) {
        if (source == Sources[i]) return static_cast<LoggerSource>(i);
    }
    return LoggerSource::none;
}

LoggerDestination Logger::string2dest(std::string destination) {
    for (int i = 0; i < static_cast<int>(LoggerDestination::__Max_Value); i++) {
        if (Destinations[i] == destination) return static_cast<LoggerDestination>(i);
    }
    return LoggerDestination::none;
}

std::string Logger::source2string(LoggerSource source) {
    return Sources[static_cast<int>(source)];
}

std::string Logger::dest2string(LoggerDestination dest) {
    return Destinations[static_cast<int>(dest)];
}


// -------------------------------------------------------------
// --- Properties
// -------------------------------------------------------------

void Logger::setSyslogName(const std::string logname) {
    _syslogname = logname;
    closelog();
    openlog(logname.c_str(), LOG_PID | LOG_CONS, LOG_USER);
};

void Logger::enable(const LoggerSource source) {
    sourceRecs[static_cast<int>(source)].enabled = true;
};

void Logger::enable(const char *source) {
    enable(string2source(std::string(source)));
}

void Logger::disable(const LoggerSource source) {
    sourceRecs[static_cast<int>(source)].enabled = false;
};

void Logger::disable(const char *source) {
    disable(string2source(std::string(source)));
}

bool Logger::isEnabled(const LoggerSource source) {
    return sourceRecs[static_cast<int>(source)].enabled;
};

bool Logger::isEnabled(const char *source) {
    return isEnabled(string2source(std::string(source)));
}

bool Logger::rotate(const LoggerSource source) { // this must only be called by a single thread which controls all output to this file
    if(sourceRecs[static_cast<int>(source)].destination == LoggerDestination::file)
        return false;
    if(sourceRecs[static_cast<int>(source)].fileRec ==  nullptr)
        return false;
    return sourceRecs[static_cast<int>(source)].fileRec->rotate();
};

bool Logger::flush(const LoggerSource source) { // this must only be called by a single thread which controls all output to this file
    if(sourceRecs[static_cast<int>(source)].destination != LoggerDestination::file)
        return false;
    if(sourceRecs[static_cast<int>(source)].fileRec ==  nullptr)
        return false;
    return sourceRecs[static_cast<int>(source)].fileRec->flush();
};

bool Logger::setLogOutput(const LoggerSource source, const LoggerDestination destination, const std::string filename,
                          const bool alsoEnable) {

    if (sourceRecs[static_cast<int>(source)].destination == LoggerDestination::file) {  // unlink file if previously set
        rmFileLink(sourceRecs[static_cast<int>(source)].fileRec);
        sourceRecs[static_cast<int>(source)].fileRec = nullptr;
    }
    if (destination == LoggerDestination::file) {
        if (!setFilename(source, filename))
            return false;
    }

    if (destination == LoggerDestination::syslog)
        setSyslogLevel(source, filename);

    setDestination(source, destination);

    if (destination == LoggerDestination::none)
        disable(source);
    else if (alsoEnable)
        enable(source);
    return true;
}

void Logger::setFormat(const LoggerSource source, bool no_format, bool show_tag, bool show_func, bool func_last, bool show_thread_id) {
    sourceRecs[static_cast<int>(source)].no_format = no_format;  // used for logs that do not required any further formating
    sourceRecs[static_cast<int>(source)].show_source_category = show_tag;
    sourceRecs[static_cast<int>(source)].show_funct_line = show_func;
    sourceRecs[static_cast<int>(source)].funct_line_last = func_last;
    sourceRecs[static_cast<int>(source)].funct_line_last = show_thread_id;
};

void Logger::setMultiFormat(std::vector <LoggerSource> *source_list, bool no_format, bool show_tag, bool show_func,
                            bool func_last, bool show_thread_id) {
    for (std::vector<LoggerSource>::iterator i = source_list->begin(); i != source_list->end(); i++) {
        setFormat(*i, no_format, show_tag, show_func, func_last, show_thread_id);
    }
}

FileRec *Logger::findFileRec(std::string filename) {
    if (!Files.empty()) {
        for (std::vector<FileRec*>::iterator i = Files.begin(); i != Files.end(); i++) {
            if ((*i)->filename == filename)
                return (*i);
        }
    }
    return nullptr;
}

void Logger::deleteFileEntry(std::string filename) {
    if (!Files.empty()) {
        for (std::vector<FileRec*>::iterator i = Files.begin(); i != Files.end(); i++) {
            if ((*i)->filename == filename) {
                Files.erase(i);
                delete *i;
                return;
            }
        }
    }
}

FileRec *Logger::addFile(std::string filename, bool unbuffered) {
    FileRec *fileRec = findFileRec(filename);
    if (fileRec == nullptr) {        // new unique filename - add to Files and open
        fileRec = new FileRec(filename, unbuffered);
        fileRec->open();
        Files.push_back(fileRec);
    } else {
        fileRec->link_count++;
    }
    return fileRec;
};

void Logger::rmFileLink(FileRec *fileRec) {
    
    if (fileRec->link_count > 1) {
        fileRec->link_count--;
    } else {
        // link count will now be zero, close file, delete stream and remove record
        fileRec->close();
        deleteFileEntry(fileRec->filename);
    }
}

void Logger::setDockerMode() {
    // docker stdout/stderr are not in sync
    // so for debugging send everything to stderr (unbuffered)
    setDestination(LoggerSource::info, LoggerDestination::stderr);
    setDestination(LoggerSource::error, LoggerDestination::stderr);
    setDestination(LoggerSource::warning, LoggerDestination::stderr);
    setDestination(LoggerSource::accesslog, LoggerDestination::stdout);
}


// -------------------------------------------------------------
// --- Public Functions
// -------------------------------------------------------------

void Logger::log(const LoggerSource source, std::string message) {
    log(source,(const std::string)"",(const std::string)"",(int)0,  message);
}

void Logger::log(const LoggerSource source, const std::string func, const std::string file, const int line, std::string message) {
    SourceRec *sourceRec = &(sourceRecs[static_cast<int>(source)]);
    std::string tag;
    std::string msg;
    tag = source2string(source);
    msg = Helper::build_message(sourceRec, tag, func, file, line, message);
    sendMessage(source, msg);
};


// -------------------------------------------------------------
// --- Private Functions
// -------------------------------------------------------------

void Logger::sendMessage(const LoggerSource source, std::string &message) {
    SourceRec *srec = &(sourceRecs[static_cast<int>(source)]);
    LoggerDestination destination = srec->destination;

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
            if (g_is_starting)
                std::cerr << message << std::endl;   // show to console as well as syslog when not daemonised
            syslog(srec->syslog_flag, "%s", message.c_str());
            break;
        case LoggerDestination::file:
            srec->fileRec->write(message);
            break;
        case LoggerDestination::__Max_Value:
            break;
    }

}

void Logger::setDestination(const LoggerSource source, const LoggerDestination destination) {
    sourceRecs[static_cast<int>(source)].destination = destination;
}

bool Logger::setSyslogLevel(const LoggerSource source, const std::string level) {

    int loglevel = LOG_INFO;

    if (level == "LOG_ERR")
        loglevel = LOG_ERR;
    else if (level == "LOG_WARNING")
        loglevel = LOG_WARNING;
    else if (level == "LOG_INFO")
        loglevel = LOG_INFO;
    else if (level == "LOG_DEBUG")
        loglevel = LOG_DEBUG;
    else if (level == "LOG_ALERT")
        loglevel = LOG_ALERT;
    else if (level == "LOG_CRIT")
        loglevel = LOG_CRIT;
    else if (level == "LOG_NOTICE")
        loglevel = LOG_NOTICE;
    else if (level == "LOG_EMERG")
        loglevel = LOG_EMERG;

    sourceRecs[static_cast<int>(source)].syslog_flag = loglevel;
    return true;
}

bool Logger::setFilename(const LoggerSource source, const std::string filename) {

    std::string name;

    if (filename.empty()) {
        return false;
    }
    if (filename.front() == '/')    // absolute path
        name = filename;
    else        // relative to __LOGLOCATION
        name = std::string(__LOGLOCATION) + filename;

    bool unbuffered = false;
    std::size_t pos = name.find_last_of(':');
    if ( pos > 0 ) {
        if (name.length() > pos+1 )
            unbuffered = name.at(pos+1) == 'u';
        name = name.substr(0, pos);
    }

    FileRec *file_rec = addFile(name, unbuffered);
    if (file_rec == nullptr) {
        std::cerr << "Null returned from addFile()" << std::endl;
        return false;
    }

    sourceRecs[static_cast<int>(source)].fileRec = file_rec;

    return true;
}

