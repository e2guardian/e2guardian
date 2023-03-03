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
#include <sys/socket.h>
#include <netdb.h>
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
    setSyslogName(PACKAGE);
    // set up default output formats
    // bools are no_format, show_tag, show_func, func_last
    setMultiFormat(&working_logs,true,false,false,false,false,false);
    setMultiFormat(&working_messages,false,false,false,false, true, true);
    setMultiFormat(&debug_messages,false,false,true, true, true, true);   // this can be overwritten by the debuglevel option

    setFormat(LoggerSource::storytrace,false,false,false,false,true, true);

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
                if ((*i)->open) {
                    ((*i)->file_stream)->close();
                    delete ((*i)->file_stream);
                }
                delete *i;
            }
        }
    }
    if (!Udps.empty()) {
        for (std::vector<UdpRec *>::iterator i = Udps.begin(); i != Udps.end(); i++) {
            if (*i != nullptr) {
                if ((*i)->open) {
                    ((*i)->socket)->close();
                    delete ((*i)->socket);
                }
                delete *i;
            }
        }
    }
}

// -------------------------------------------------------------
// --- Helper
// -------------------------------------------------------------

struct Logger::Helper {
    static std::string build_message(SourceRec *rec, std::string &prepend, const std::string &func,
                                     const std::string &file, const int &line, std::string what) {
        // TODO: add time properly in separate commit PIP
        std::string message;
        if (rec->show_timestamp_active) {
            time_t t = time(NULL);
            message = (std::to_string((long)t));
            message += " ";
        }
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
        if( rec->destination == LoggerDestination::udp) {
            message.append("\n");
        }
        return message;
    }
};

class Logger::Udp {
public:

};

bool UdpRec::send(std::string &msg) {
    if (socket == nullptr) {
        std::cerr << "socket is null" << std::endl;
    } else {
        //std::cerr << "socket is not null" << std::endl;
        if (!socket->writeString(msg)) {
            std::cerr << "udp write to " << host << " failed";
            return false;
        };
        //std::cerr << "udp write to " << host << " OK";
    }
    return true;
}

bool FileRec::write(std::string &msg) {
    if (file_stream == nullptr) {
        std::cerr << "file_stream is null" << std::endl;
    } else {
//        std::cerr << "file_stream is not null" << std::endl;
        *file_stream << msg << std::endl;
        if (file_stream->fail()) {
            //std::cerr << "log write to " << filename << " failed";
            return false;
        }
//        std::cerr << "log write to " << filename << " OK";
    }
    return true;
}
bool FileRec::flush() {
    if(file_stream == nullptr)
        return false;
    file_stream->flush();
    return true;
}

bool FileRec::rotate() {   // this must only be called by a single thread which controls all output to this file
    if(file_stream == nullptr)
        return false;
    std::string rfn = filename;
    mode_t old_umask;
    old_umask = umask(S_IWGRP | S_IWOTH);
    rfn += ".old";
    if(link(filename.c_str(), rfn.c_str()) == 0) {
        unlink(filename.c_str());
        file_stream->close();
        delete file_stream;
        file_stream = new std::ofstream(filename.c_str(), std::ios::app);
        umask(old_umask);
        return true;
    }
    umask(old_umask);
    return false;

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
    _logname = logname;
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
    if(sourceRecs[static_cast<int>(source)].destination != LoggerDestination::file)
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
    if (destination == LoggerDestination::file) {
        if (!setFilename(source, filename))
            return false;
    } else if (sourceRecs[static_cast<int>(source)].destination == LoggerDestination::file) {  // unlink file if previously set
        rmFileLink(sourceRecs[static_cast<int>(source)].fileRec);
        sourceRecs[static_cast<int>(source)].fileRec = nullptr;
    }

    if (destination == LoggerDestination::udp) {
        if (!setUdpname(source, filename))
            return false;
    } else if (sourceRecs[static_cast<int>(source)].destination == LoggerDestination::udp) {  // unlink file if previously set
        rmUdpLink(sourceRecs[static_cast<int>(source)].udpRec);
        sourceRecs[static_cast<int>(source)].udpRec = nullptr;
    }

   // if (destination == LoggerDestination::udp) {
   //     if (!setUdpDestination(source, filename))
   //         return false;
  //  }

    if (destination == LoggerDestination::syslog) {
        setSyslogLevel(source, filename);
        sourceRecs[static_cast<int>(source)].show_timestamp_active = false;
    } else {
        if (sourceRecs[static_cast<int>(source)].show_timestamp) {
            sourceRecs[static_cast<int>(source)].show_timestamp_active = true;
        }
    };

    setDestination(source, destination);

    if (destination == LoggerDestination::none)
        disable(source);
    else if (alsoEnable)
        enable(source);
    return true;
}

void Logger::setFormat(const LoggerSource source, bool no_format, bool show_tag, bool show_func, bool func_last, bool show_thread_id, bool show_timestamp) {
    sourceRecs[static_cast<int>(source)].no_format = no_format;  // used for logs that do not required any further formating
    sourceRecs[static_cast<int>(source)].show_source_category = show_tag;
    sourceRecs[static_cast<int>(source)].show_funct_line = show_func;
    sourceRecs[static_cast<int>(source)].funct_line_last = func_last;
    sourceRecs[static_cast<int>(source)].show_thread_id = show_thread_id;
    sourceRecs[static_cast<int>(source)].show_timestamp = show_timestamp;
};

void Logger::setMultiFormat(std::vector <LoggerSource> *source_list, bool no_format, bool show_tag, bool show_func,
                            bool func_last, bool show_thread_id, bool show_timestamp) {
    for (std::vector<LoggerSource>::iterator i = source_list->begin(); i != source_list->end(); i++) {
        setFormat(*i, no_format, show_tag, show_func, func_last, show_thread_id, show_timestamp);
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
                if ((*i)->file_stream != nullptr) {
                    ((*i)->file_stream)->close();
                    delete (*i)->file_stream;
                    (*i)->file_stream = nullptr;
                }
                delete *i;
                Files.erase(i);
                return;
            }
        }
    }
}

FileRec *Logger::addFile(std::string filename) {
    FileRec *fileRec = findFileRec(filename);
    if (fileRec == nullptr) {        // new unique filename - add to Files and open
        FileRec* fileRec1 = new FileRec;
        fileRec1->filename = filename;
        fileRec1->link_count = 1;
        Files.push_back(fileRec1);
        fileRec = findFileRec(filename);
        if (fileRec == nullptr) {
            std::cerr << "failure to find new Files record for " << filename << std::endl;
            return nullptr;
        }
        mode_t old_umask;
        old_umask = umask(S_IWGRP | S_IWOTH);
        //       fileRec->file_stream = fopen(filename.c_str(), "a");
        fileRec->file_stream = new std::ofstream(filename.c_str(), std::ios::app);
        if (!fileRec->file_stream) {
            std::cerr << "Failed to open/create logfile: " << filename << " (check ownership and access rights)"
                      << std::endl;
            deleteFileEntry(filename);
            umask(old_umask);
            return nullptr;
        }
        umask(old_umask);
        //std::cerr << "Opened new file: " << filename << std::endl;
        //std::cerr << "Opened new filename in record : " << fileRec->filename << std::endl;
        fileRec->open = true;
        //std::cerr << "File link count is " << fileRec->link_count << std::endl;
    } else {
        fileRec->link_count++;
        //std::cerr << "File link count is " << fileRec->link_count << std::endl;
    }
    return fileRec;
};

void Logger::rmFileLink(FileRec *fileRec) {
    if(fileRec == nullptr)
        return;
    if (fileRec->link_count > 1) {
        fileRec->link_count--;
        //std::cerr << "rmFileLink File link count is " << fileRec->link_count << std::endl;
        return;
    }
    // link count will now be zero, close file, delete stream and remove record
    //std::cerr << "Close and delete " << fileRec->filename << std::endl;
    //fclose(fileRec->file_stream);
    if (fileRec->file_stream != nullptr) {
        fileRec->file_stream->close();
        delete fileRec->file_stream;
        fileRec->file_stream = nullptr;
    }
    deleteFileEntry(fileRec->filename);
}


void Logger::setDockerMode() {
    // docker stdout/stderr are not in sync
    // so for debugging send everything to stderr (unbuffered)
    std::cerr << "setDockerMode " << std::endl;
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
    if (sourceRec->no_format && sourceRec->destination == LoggerDestination::file) {
        sendMessage(source, message);
    } else {
        std::string tag;
        std::string msg;
        tag = source2string(source);
        msg = Helper::build_message(sourceRec, tag, func, file, line, message);
        sendMessage(source, msg);
    }
};


// -------------------------------------------------------------
// --- Private Functions
// -------------------------------------------------------------

void Logger::sendMessage(const LoggerSource source, std::string &message) {
    SourceRec *srec = &(sourceRecs[static_cast<int>(source)]);
    LoggerDestination destination = srec->destination;

    //std::cerr << "sendMessage  source " << source2string(source) << " dest " << dest2string(destination) << std::endl;

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
            if (srec->fileRec == nullptr) {
                std::cerr << "dest fileRec is nullptr" << std::endl;
            } else {
                if (!srec->fileRec->open )
                    std::cerr << "Log file output stream is closed";
                else {
                    // std::cerr << "Log filename is " << srec->fileRec->filename << std::endl;
                    // std::cerr << "log msg: " << message << std::endl;
                    srec->fileRec->write(message);
                }
            }
            break;
        case LoggerDestination::udp:
            if (srec->udpRec == nullptr) {
                std::cerr << "dest udpRec is nullptr" << std::endl;
            } else {
               // std::cerr << "Log udp is " << srec->udpRec->host << std::endl;
                if(srec->udpRec->send(message)) {
                 //   std::cerr << "udp message sent"  << std::endl;
                } else {
                    std::cerr << "udp message failed" << std::endl;
                }
            }
            break;
        case LoggerDestination::__Max_Value:
            break;
    }

}

void Logger::setDestination(const LoggerSource source, const LoggerDestination destination) {
    sourceRecs[static_cast<int>(source)].destination = destination;
    // std::cerr << "Logger::setDestination " << source2string(source) << " -> " << dest2string(destination) << std::endl;
}

bool Logger::setSyslogLevel(const LoggerSource source, const std::string filename) {

    int loglevel = LOG_INFO;

    if (filename == "LOG_ERR")
        loglevel = LOG_ERR;
    else if (filename == "LOG_WARNING")
        loglevel = LOG_WARNING;
    else if (filename == "LOG_INFO")
        loglevel = LOG_INFO;
    else if (filename == "LOG_DEBUG")
        loglevel = LOG_DEBUG;
    else if (filename == "LOG_ALERT")
        loglevel = LOG_ALERT;
    else if (filename == "LOG_CRIT")
        loglevel = LOG_CRIT;
    else if (filename == "LOG_NOTICE")
        loglevel = LOG_NOTICE;
    else if (filename == "LOG_EMERG")
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

    if (sourceRecs[static_cast<int>(source)].destination == LoggerDestination::file) { 
        rmFileLink(sourceRecs[static_cast<int>(source)].fileRec);
        sourceRecs[static_cast<int>(source)].fileRec = nullptr;
    }

    FileRec *file_rec = addFile(name);
    if (file_rec == nullptr) {
        std::cerr << "Null returned from addFile()" << std::endl;
        return false;
    }

    sourceRecs[static_cast<int>(source)].fileRec = file_rec;
    // std::cerr << "Lookup filename after added to source_dests is " 
    //           << sourceRecs[static_cast<int>(source)].fileRec->filename << std::endl;

    return true;
}

bool Logger::setUdpname(const LoggerSource source, const std::string filename) {

    std::string host="";
    String port;
    String temp = filename;


    if (filename.empty()) {
        return false;
    }
    host = temp.before(":");
    port = temp.after(":");

    if (sourceRecs[static_cast<int>(source)].destination == LoggerDestination::udp) { //
        rmUdpLink(sourceRecs[static_cast<int>(source)].udpRec);
        sourceRecs[static_cast<int>(source)].udpRec = nullptr;
    }

    UdpRec *udp_rec = addUdp(host, port.toInteger());
    if (udp_rec == nullptr) {
        std::cerr << "Null returned from addUdp()" << std::endl;
        return false;
    }

    sourceRecs[static_cast<int>(source)].udpRec = udp_rec;
    //    std::cerr << "Lookup filename after added to source_dests is " 
    //              << source_dests[static_cast<int>(source)].fileRec->filename << std::endl;

    return true;
}
#ifdef NOT_DEF
bool Logger::setUdpDestination(const LoggerSource source, const std::string udp_destination) {

    std::string host="";
    std::string port="";

    std::size_t pos = udp_destination.find_last_of(':');
    if ( pos > 0 ) {
        host = udp_destination.substr(0,pos);
        port = udp_destination.substr(pos+1);
    }
    if (host.empty() || port.empty())
    {
        std::cerr << "missing host and port for UDP destination " << udp_destination << std::endl;
        return false;
    }

    sourceRecs[static_cast<int>(source)].host = host;
    sourceRecs[static_cast<int>(source)].port = port;
    return true;
}
#endif


UdpRec *Logger::addUdp(std::string host, int port) {
    UdpRec *udpRec = findUdpRec(host, port);
    if (udpRec == nullptr) {        // new unique udpname - add to Udps and open
        UdpRec *udpRec1 = new UdpRec;
        udpRec1->host = host;
        udpRec1->port = port;
        udpRec1->link_count = 1;
        Udps.push_back(udpRec1);
        udpRec = findUdpRec(host, port);
        if (udpRec == nullptr) {
            std::cerr << "failure to find new Udps record for " << host << ":" << port << std::endl;
            return nullptr;
        }
        int rc = -1;
        String shost(host);
        if (shost.isIp()) {
          //  std::cerr << "host is an ip" << std::endl;
            udpRec->socket = new UdpSocket;
            rc = udpRec->socket->connect(host, port);
        } else { // do dns lookup
          // std::cerr << "host is NOT an ip" << std::endl;
            struct addrinfo hints, *addrs, *addr;
            memset(&hints, 0, sizeof(addrinfo));

            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            hints.ai_flags = 0;
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;

            String sport = port;

            int status = getaddrinfo(host.c_str(), NULL, &hints, &addrs);
            if (status != 0) {
                std::cerr << "can not find host " << host << std::endl;
                return nullptr;
            }
            char t[256];
            for (addr = addrs; addr != nullptr; addr = addr->ai_next) {
                getnameinfo(addr->ai_addr, addr->ai_addrlen, t, sizeof(t), NULL, 0, NI_NUMERICHOST);
                udpRec->socket = new UdpSocket;
                if ((rc = udpRec->socket->connect(t, port)) < 0)
                    continue;
                else
                    break;
            }
        }
        if (rc < 0) { // so not able to connect on any ip
            std::cerr << "can not open socket to " << host << std::endl;
            deleteUdpEntry(host, port);
            return nullptr;
        }
        //std::cerr << "Opened new udpname in record : " << udpRec->host << " port " <<udpRec->port << std::endl;
        udpRec->open = true;
        //std::cerr << "Udp link count is " << udpRec->link_count << std::endl;
    } else {
        udpRec->link_count++;
        //std::cerr << "Udp link count is " << udpRec->link_count << std::endl;
    };
    return udpRec;
}

    void Logger::rmUdpLink(UdpRec *udpRec) {
        if (udpRec == nullptr)
            return;
        if (udpRec->link_count > 1) {
            udpRec->link_count--;
            //std::cerr << "rmUdpLink Udp link count is " << udpRec->link_count << std::endl;
            return;
        }
        // link count will now be zero, close udp, delete stream and remove record
        //std::cerr << "Close and delete " << udpRec->udpname << std::endl;
        //fclose(udpRec->udp_stream);
        if (udpRec->socket != nullptr) {
            udpRec->socket->close();
            delete udpRec->socket;
            udpRec->socket = nullptr;
        }
        deleteUdpEntry(udpRec->host, udpRec->port);
    }


UdpRec *Logger::findUdpRec(std::string host, int port) {
    if (!Udps.empty()) {
        for (std::vector<UdpRec*>::iterator i = Udps.begin(); i != Udps.end(); i++) {
            if (((*i)->host == host) && ((*i)->port == port))
                return (*i);
        }
    }
    return nullptr;
}

void Logger::deleteUdpEntry(std::string host, int port) {
    if (!Udps.empty()) {
        for (std::vector<UdpRec*>::iterator i = Udps.begin(); i != Udps.end(); i++) {
            if (((*i)->host == host) && ((*i)->port == port)) {
                if ((*i)->socket != nullptr) {
                    ((*i)->socket)->close();
                    delete (*i)->socket;
                    (*i)->socket = nullptr;
                }
                delete *i;
                Udps.erase(i);
                return;
            }
        }
    }
}
