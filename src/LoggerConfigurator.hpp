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

class LoggerConfigurator{
  public:
  LoggerConfigurator(Logger* logger);
  ~LoggerConfigurator();

  static const String PREFIX;

  // option: log_{source}={output}[, filename]
  void configure(const std::string option);

  private:
  Logger* _logger;

};

#endif