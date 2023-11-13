// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "ImageContainer.hpp"
#include "Logger.hpp"

#include <iostream>
#include <fstream>
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <limits.h>

// GLOBALS


// IMPLEMENTATION

ImageContainer::ImageContainer()
{
    image = NULL;
    imagelength = 0;
}

ImageContainer::~ImageContainer()
{
    delete[] image;
}

// wipe the loaded image
void ImageContainer::reset()
{
    delete[] image;
    image = NULL;
    mimetype = "";
    imagelength = 0;
}

// send image to client
//void ImageContainer::display(Socket *s)
bool ImageContainer::display(Socket *s)
{
    DEBUG_debug("Displaying custom image file mimetype: ", mimetype);
    s->writeString("Content-type: ");
    s->writeString(mimetype.toCharArray());
    s->writeString("\n\n");

    if (!s->writeToSocket(image, imagelength, 0, s->getTimeout()))
//        throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
         return false;
    return true;
}


bool ImageContainer::display_hb(String &eheader, String &ebody) {
    ebody = image;
    eheader += "Content-type: " ;
    eheader +=   mimetype.toCharArray();
    eheader += "\r\nContent-Length: ";
    eheader += std::to_string(ebody.size());
    eheader +=  "\r\n\r\n";
    return true;
}

// read image from file
bool ImageContainer::read(const char *filename)
{
    String temp(filename);
    temp.toLower();

    if (temp.endsWith(".jpg") || temp.endsWith(".jpeg") || temp.endsWith(".jpe")) {
        mimetype = "image/jpg";
    } else if (temp.endsWith("png"))
        mimetype = "image/png";
    else if (temp.endsWith("swf"))
        mimetype = "application/x-shockwave-flash";
    else {
        mimetype = "image/gif";
    }

    std::ifstream imagefile;
    imagefile.open(filename, std::ifstream::binary);
    imagefile.seekg(0, std::ios::end);
    imagelength = imagefile.tellg();
    imagefile.seekg(0, std::ios::beg);

    if (imagelength) {
        if (image != NULL)
            delete[] image;
        image = new char[imagelength + 1];
        imagefile.read(image, imagelength);
        if (!imagefile.good()) {
            E2LOGGER_error("Error reading custom image file: ", filename);
            return false;
        }
    } else {
        E2LOGGER_error("Error reading custom image file: ", filename);
        return false;
    }
    imagefile.close();
    return true;
}
