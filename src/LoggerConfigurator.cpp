
// LoggerConfigurator - reading strings for configuring the Logger
//
// Author  : Klaus-Dieter Gundermann
// Created : 30.06.2020
//
// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <algorithm>
// #include <string>
#include "LoggerConfigurator.hpp"
#include "String.hpp"

// -------------------------------------------------------------
// --- Constructor
// -------------------------------------------------------------
LoggerConfigurator::LoggerConfigurator(Logger *logger) {
    _logger = logger;
};

LoggerConfigurator::~LoggerConfigurator() {
    _logger = NULL;
};

const String LoggerConfigurator::Prefix("log_");

// -------------------------------------------------------------
// --- Public Functions
// -------------------------------------------------------------

bool LoggerConfigurator::configure(LoggerSource source, const std::string option) {
    String line(option);
    line.removeChar(' ');
    std::string destination;
    String filename;
    if(line.contains(":")) {
        destination = line.before(":");
        filename = line.after(":");
        filename.removeChar('\'');
    } else {
        destination = line;
    }

    LoggerDestination dst = _logger->string2dest(destination);

    DEBUG_config("LoggerConfig:", " source:", _logger->source2string(source), " destination:", destination, " filename:", filename);

    return _logger->setLogOutput(source, dst, filename,true);
}

bool LoggerConfigurator::configure(const std::string option) {
    String line(option);
    line.removeChar(' ');
    if (!line.startsWith(Prefix)) return false;

    size_t pos1 = line.find("=", 0);
    if (pos1 == std::string::npos) return false;

    std::string source = line.substr(Prefix.size(), pos1 - Prefix.size());

    std::string reduced_option;

    reduced_option = line.substr(pos1 + 1);
    LoggerSource src = _logger->string2source(source);

    return configure(src, reduced_option);
};

bool LoggerConfigurator::debuglevel(const std::string option) {
    String line(option);
    line.removeChar(' ');

    String types, dest, file;
    LoggerDestination dst = LoggerDestination::none;

    if (line.contains(":")) {
        types = line.before(":");
        dest = line.after(":");
        if (dest.contains(":")) {
            file = dest.after(":");
            dest = dest.before(":");
        }
        dst = _logger->string2dest(dest);
    } else {
        types = line;
    }

    //std::cerr << "types:" << types << " dest:" << dest << " LoggerDestination " << _logger->dest2string(dst) << " file:" << file << std::endl;

    if (types.contains("ALL")) {
        String temp = types.before("ALL");
        temp += "HIGH,LOW";
        temp += types.after("ALL");
        types = temp;
    }

    if (types.contains("HIGH")) {
        String temp = types.before("HIGH");
        temp += "icap,avscan,auth,dwload,proxy,thttps";
        temp += types.after("HIGH");
        types = temp;
    }

    if (types.contains("LOW")) {
        String temp = types.before("LOW");
        temp += "debug,trace,network,regexp,story,config,content";
        temp += types.after("LOW");
        types = temp;
    }
    types.toLower();

    //std::cerr << types << std::endl;

    while (!types.empty()) {
        String temp;
        if (types.contains(",")) {
            temp = types.before(",");
            types = types.after(",");
        } else {
            temp = types;
            types = "";
        }

       // std::cerr << "dealing with " << temp << " types left are " << types << std::endl;

        bool neg = temp.startsWith("-");
        if (neg)
            temp = temp.after("-");

        LoggerSource src = _logger->string2source(temp.c_str());
        if (src == LoggerSource::none) {
            std::cerr << "Error: unknown debuglevel " << temp << std::endl;
            return false;
        };

        if (neg) {
            _logger->disable(src);
        } else {
            if (dst != LoggerDestination::none) {
                // E2LOGGER_info("LoggerConfig:", " source:", src, " destination:", dest, " filename:", file );
                _logger->setLogOutput(src, dst, file);
      //          std::cerr << _logger->source2string(src) << " " << _logger->dest2string(dst) << " " << file << std::endl;
            } else {    // assume useing defaults so just enable
                _logger->enable(src);
            }
        }
    }
    return true;
}

void LoggerConfigurator::debugformat(int fmt) {
    switch (fmt) {
        case 1:
            _logger->setMultiFormat(&_logger->debug_messages, false, false, true, true, true);
            break;
        case 2:
            _logger->setMultiFormat(&_logger->debug_messages, false, false, true, false, true);
            break;
        case 3:
            _logger->setMultiFormat(&_logger->debug_messages, false, false, false, false, true);
            break;
        case 4:
            _logger->setMultiFormat(&_logger->debug_messages, false, true, true, true, true);
            break;
        case 5:
            _logger->setMultiFormat(&_logger->debug_messages, false, true, true, false, true);
            break;
        case 6:
            _logger->setMultiFormat(&_logger->debug_messages, false, true, false, false, true);
            break;
    }
}


