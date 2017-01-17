//Declares the HTMLTemplate class, for displaying template-based banned pages to clients

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_HTMLTEMPLATE
#define __HPP_HTMLTEMPLATE

// INCLUDES

#include "String.hpp"
#include "Socket.hpp"

#include <deque>
#include <string>

// DECLARATIONS

class HTMLTemplate
{
    public:
    // string list for holding the template
    // public so that it can be accessed directly for display without using
    // the default set of placeholders
    std::deque<String> html;

    // wipe the loaded template
    void reset();

    // load in a template from the given file, looking for placeholder strings (reason, URL, category etc.)
    // optionally, provide your own set of placeholders
    bool readTemplateFile(const char *filename, const char *placeholders = NULL);

    // fill in the template with the given info and send it to the client over the given socket
    // only useful if you used the default set of placeholders
    void display(Socket *s, String *url, std::string &reason, std::string &logreason, std::string &categories,
        std::string *user, std::string *ip, std::string *host, int filtergroup, String grpname, String &hashed);

    private:
    // add a string to the list
    void push(String s);
};

#endif
