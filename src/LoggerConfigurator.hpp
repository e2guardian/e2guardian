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

class LoggerConfigurator{
  public:
  LoggerConfigurator(Logger* logger);
  ~LoggerConfigurator();

  static const std::string PREFIX;

  // option: log_{source}={output}[, filename]
  void configure(const std::string option);

  private:
  Logger* _logger;

  std::string replaceinString(std::string str, std::string tofind, std::string toreplace)
  {
    size_t position = 0;
    for ( position = str.find(tofind); position != std::string::npos; position = str.find(tofind,position) )
    {
      str.replace(position ,1, toreplace);
    }
    return(str);
  }

};

#endif