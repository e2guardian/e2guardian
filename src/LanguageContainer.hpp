// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_LANGUAGECONTAINER
#define __HPP_LANGUAGECONTAINER


// INCLUDES
#include <deque>

#include "String.hpp"


// DECLARATIONS

class LanguageContainer
{
public:
	void reset();

	bool readLanguageList(const char *filename);

	const char *getTranslation(const unsigned int index);

private:
	  std::deque<unsigned int > keys;
	  std::deque<String > values;

};

#endif
