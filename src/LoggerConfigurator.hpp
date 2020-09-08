// LoggerConfigurator - reading strings for configuring the Logger
//
// Author  : Klaus-Dieter Gundermann
// Created : 30.06.2020
//
// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LOGGER_CONFIG
#define __HPP_LOGGER_CONFIG

#include "Logger.hpp"
#include "String.hpp"

class LoggerConfigurator {
public:
    LoggerConfigurator(Logger *logger);

    ~LoggerConfigurator();

    const static String Prefix;

    // option: log_{source}={output}[, filename]
    bool configure(const std::string option);
    bool configure(LoggerSource source, const std::string option);

    // debuglevel option  debuglevel = 'ALL,-ICAP:destination:file
    bool debuglevel(const std::string option);

    void debugformat(int fmt);

private:
    Logger *_logger;

};

#endif