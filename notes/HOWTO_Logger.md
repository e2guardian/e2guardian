# Logger and LoggerConfigurator

Starting with v5.5 we implemented a central logger.
  
It can log messages from different sources and routes them to different destinations.  

It is be used for normal messages from the application to the user, to direct the output
of logs as well as for debug messages. 

It is configured using the config file. Debug settings can also be made on the commandline using
 the -d option.

## Logger

Currently the following are implemented:

Working Messages
- info : normal messages from the application, default output: stdout
- error: error messages from the application, default output: stderr
- warning: warning messages from the application, default output: stderr

Working Logs
- accesslog: access log , default output access.log in __LOGLOCATION
- dstatslog: dynamic statisics log,  default is no destination
- requestlog: optional request log,  default is no destination
- alertlog: optional alert log,  default is no destination

Storyboard tracing
- storytrace: storyboard tracing

High Level Debugs - enabled when e2guardian is complied with '--with-debug_high'
	Note all debugs are disabled by default and can be enabled with the debuglevel option

- proxy: logs flow of a user request (explicit/tranparent proxy)
- thttps: logs flow of a user request on transparent https port 
- icap: logs flow of a request on icap port 
- auth: logs flow of authentication (including auth plugins)
- avscan: logs flow of AV scan (including AV plugins)
- dwload: logs flow of download managers (including download plugins)

Low Level Debugs - enabled when e2guardian is complied with '--with-debug_low'

- config: logs infos about reading the configuration files
- trace: debugging messages about the program FLOW (entering/leaving functions)
- story:  debugging messages for handling the STORYBOARD
- regexp: debugging messages for handling REGEXP (regular expressions)
- network: debugging messages for handling the NETWORK
- content: debugging messages for handling CONTENT CHECKING
- debug: debugging messages about the program STATE (variables)

Note: Production systems may be complied with --with-debug_high but should never be complied
 with --with-debug-low

Log messages can be sent to the following DESTINATIONS:

- stdout
- stderr
- syslog
- file
- udp
- none (= disable logging)

## LoggerConfigurator

With the LoggerConfigurator it is possible to configure the logger, either by using an option on the commandline or through the config file 'e2guardian.conf'.

To configure the output for working messages, working logs or storytrace sources use the following
 syntax in e2guardian.conf:

- `set_{source} = '{destination}[:[filename|sysloglevel|host:upd_port]'`

e.g.

- for sending error messages to stderr use  set_error = 'stderr' 
- for sending error messages to syslog at level LOG_ERR use  set_error = 'syslog:LOG_ERR'  
- for sending the access logs to a file use set_accesslog = 'file:/var/log/e2guardian/access.log'
- for sending the access logs via udp use set_accesslog = 'udp:my_log_collector_host:upd_port'

To configure debug use the following syntax in e2guardian.conf or after -d on invocking e2guardian:

- debuglevel = 'type1,type2[:destination[:filename|sysloglevel|host:udp_port]]

e.g 

(In e2guardian.conf)
- to switch on proxy debug to default destination - debuglevel = 'proxy'
- to switch on proxy and auth debug to default destination - debuglevel = 'proxy,auth'
- to switch on ALL debugs, but not auth to default destination - debuglevel = 'ALL,-auth'

- to specify destination
  debuglevel = 'proxy:stderr'
  debuglevel = 'proxy,auth:file:debug.log'
  etc.

(On command line)
Add flags above to -d option e.g.

e2guardian ... -d proxy
e2guardian ... -d proxy,auth
e2guardian ... -d 'ALL,-auth'
e2guardian ... -d proxy,auth:file:debug.log

For more details on debuglevel please see example e2guardian.conf

Debug output format

A number of different format options can be deployed for debugs
See the debugformat option in e2guardian.conf for details


## HOWTOs for Developers

For each source there is a macro, which can be used to log messages, e.g.:

Working Messages  
- E2LOGGER_error(...); 
- E2LOGGER_info(...);
etc.

Working Logs 
- E2LOGGER_accesslog(message);
- E2LOGGER_storytrace(message);
etc.

Debugs
- DEBUG_proxy(...);
- DEBUG_debug(...);
etc.

All variadic macros will accept a list of variables of any type accepted by ostream and will
convert these into output format. So, for example:-

int x = 5;
String s = "Test String";
std:string t = "string";
DEBUG_proxy("The value of int x is ", x, " and String s is ", s, " and std::string t is ",t); 

will output "The value of int x is 5 and String s is Test String and std::string t is string" 

Warning: Each macro generates an if statement like:-

	if(flag) vlog(.....)

	so always place within braces if it is the subject of a surrounding 'if' 

	if(condition) {
	   DEBUG_debug("Some message");
	} else {
	   DEBUG_debug("Another message");
	};

	is OK,  BUT 

	if(condition) 
	   DEBUG_debug("Some message");
	else 
	   DEBUG_debug("Another message");
	
	is NOT OK and is likely to generate at least a complier warning

When a DEBUG_mmm(...) macro is not compliled then is mapped to blank by the preprocesor,
 effectively removing the line from the complied program.



You may enable or disable a specific logger in code:

- `e2logger.enable(LoggerSource::debug);`

You may even enable/disable a specific logger in gdb:

- `(gdb) call e2logger.disable("debug")`

For adding a new logger source (tag, category) add:

- to the Enum `LoggerSource` in Logger.hpp
- to the vector `Sources` in Logger.cpp
- to the macro definitions at the end of Logger.hpp

### Running in a Docker container

when running e2guardian in a docker container, all output should be directed to stdout/stderr  
(see <https://docs.docker.com/config/containers/logging/> ),  
so that the docker daemon can collect it (and show it with `docker --logs ...')  

You can enable the dockermode in code with `e2logger.setDockerMode();`

## Obsoletes

The new Logger obsoletes/replaces the following:

- e2guardian.conf:
  - logsyslog : can be replaced with 'set_accesslog = syslog:LOG_INFO'
  - nologger: is replaced with 'set_accesslog = none'
  - loglocation: can be replaced with 'set_accesslog = file:loglocation'
  - debuglevelfile: is replaced with extended debuglevel options
	i.e. debuglevel = 'debugs_needed:file:filelocation'

- Code
  - files: DebugManager.hpp/cpp
  - defines: NETDEBUG, CHUNKDEBUG, SBDEBUG, NEWDEBUG_OFF, E2DEBUG
  - vars in OptionContainer:   no_logger, log_syslog


## TODOs

- Logger Output to Email ??
- Logger Output sending to GrayLog, LogStash ?? // may covered by udp destination

(last edit: 04.01.2023)
