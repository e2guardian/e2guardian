//Implements the ConfigVar class

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "ConfigVar.hpp"

#include <fstream>


// IMPLEMENTATION

// constructor
ConfigVar::ConfigVar()
{
}

// construct & read in the given config file
ConfigVar::ConfigVar(const char *filename, const char *delimiter)
{
	int res = readVar(filename, delimiter);
}

// return the value for the named option
String ConfigVar::entry(const char *reference)
{
	return params[reference];
}

// same as above, but in handy operator form
String ConfigVar::operator[] (const char *reference)
{
	return params[reference];
}

// read in options from the given file, splitting option/value at delimiter
int ConfigVar::readVar(const char *filename, const char *delimiter)
{
	std::ifstream input(filename);
	char buffer[2048];

	params.clear();

	if (!input)
		return 1;

	while (input.getline(buffer, sizeof(buffer))) {

		char *command = strtok(buffer, delimiter);
		if (!command)
			continue;

		char *parameter = strtok(NULL, delimiter);
		if (!parameter)
			continue;

		// strip delimiters
		while (*parameter == '"' || *parameter == '\'' || *parameter == ' ')
			parameter++;
		int offset = strlen(parameter) - 1;

		while (parameter[offset] == '"' || parameter[offset] == '\'')
			parameter[offset--] = '\0';

		offset = strlen(command) - 1;
		while (command[offset] == ' ')
			command[offset--] = '\0';

		params[command] = parameter;
	}

	input.close();
	return 0;
}
