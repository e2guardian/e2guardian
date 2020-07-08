
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
LoggerConfigurator::LoggerConfigurator(Logger* logger){
  _logger = logger;
};
LoggerConfigurator::~LoggerConfigurator(){
  _logger = NULL;
};

const String LoggerConfigurator::PREFIX("log_");
 
// -------------------------------------------------------------
// --- Public Functions
// -------------------------------------------------------------

void LoggerConfigurator::configure(const std::string option)
{
  String line(option);
  line.removeChar(' ');
  if (!line.startsWith(PREFIX))  return;

  size_t pos1 = line.find("=",0);
  if (pos1 == std::string::npos ) return;

  std::string source = line.substr(PREFIX.size(), pos1 - PREFIX.size() );
  std::string destination;
  String filename;

  size_t pos2 = line.find(",", pos1);
  if (pos2 ==  std::string::npos) {
    destination = line.substr(pos1+1);
    filename = "";
  } else
  {
    destination = line.substr(pos1+1, pos2-pos1-1);
    filename = String(line.substr(pos2+1));
    filename.removeChar('\'');
  }
  
  LoggerSource src = Logger::string2source(source);
  LoggerDestination dst = Logger::string2dest(destination);
  
  logger_info("LoggerConfig:", " source:", source, " destination:", destination, " filename:", filename );
  _logger->setLogOutput(src, dst, filename);

};

 