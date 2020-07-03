# Logger and LoggerConfigurator

Starting with v5.4 we implemented a central logger.  
It can log messages from different sources and send them to different destinations.  
It can be used for normal messages from the application for the user as also debug messages for the devolper.
It can be configured through the LoggerConfigurator either on the commandline or through the config file.

## Logger

Currently the following logger SOURCES are implemented:

- info : normal messages from the application, default output: stdout
- error: error messages from the application, default output: stderr
- access: logline for every access handled by e2guardian, default output access.log in __LOGLOCATION
- config: logs infos about reading the configuration files, default output: none
- story: logs infos about the storyboard workflow when handling a request, default output: none
- icap: TBD
- icaps: TBD
- clamav: TBD
- thhtps: TBD

the following source are only enabled when e2guardian is compiled with the '--with_e2debug' and are intended to be used by the developer:

- debug: debugging messages about the program STATE (variables)
- trace: debugging messages about the program FLOW (entering/leaving functions)
- debugnet: debugging messages for handling the NETWORK
- debugsb:  debugging messages for handling the STORYBOARD
- debugchunk: TBD
- debugregexp: debugging messages for handling REGEXP (regular expressions)

Log messages can be send to the following DESTINATIONS:

- stdout
- stderr
- syslog
- file
- none (= disable logging)

## LoggerConfigurator

With the LoggerConfigurator it is possible to configure the logger, either by using an option on the commandline or through the config file 'e2guardian.conf'.

To configure the output of a logger source use the following syntax:

- `log_{source}={destination}[,=filename]`

e.g.

- for sending error messages to stderr use  `log_error=stderr`  
- for sending the access logs to a file use `log_access=/var/log/e2guardian/access.log`
- for running e2guardian with StoryBoard-Tracing enabled : `e2guardian -l log_story=stdout`

## HOWTOs for Developers

For every source the is a macro, which can be used to log messages, e.g.:  

- `log_error(...);` or `log_debug(..);`


You may enable or disable a specific logger in code: 

- `logger.enable(LoggerSource::debug);`

For adding a new logger source (tag, category) add:

- to the Enum `LoggerSource` in Logger.hpp
- to the macro definitions at the end of Logger.hpp
- to the Array `Logger::SOURCES[]` in Logger.cpp

### Running in a Docker container

when running e2guardian in a docker container, every out put should be directed to stdout/stderr  
(see <https://docs.docker.com/config/containers/logging/> ),  
so that the docker daemon can collect it (and show it with `docker --logs ...')  

You can enable the dockermode in code with `logger.setDockerMode();`

## Obsoletes

The new Logger obsoletes/replaces the following:

- e2guardian.conf:
  - logsyslog, debuglevel, debuglevelfile, nologger, storyboardtrace
  - loglocation, rqloglocation, dstatlocation
  - logconnectionhandlingerrors?, logchildprocesshandling?

- Code
  - files: DebugManager.hpp/cpp
  - defines: NETDEBUG, CHUNKDEBUG, SBDEBUG, NEWDEBUG_OFF
  - vars in OptionContainer o: logconerror, logchildprocs, log_ssl_errors?, log_location, RQlog_location, stat_location, dstat_location, dstat_log_flag, no_logger, log_syslog

## TODOs

- Logger Output to Email ??
- Logger Output sending to GrayLog, LogStash ??

(last edit: 03.07.2020)
