// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "ImageContainer.hpp"

#include <syslog.h>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <cerrno>
#include <limits.h>


// GLOBALS

extern bool is_daemonised;


// IMPLEMENTATION

ImageContainer::ImageContainer()
{
	image = NULL;
	imagelength = 0;
}

ImageContainer::~ImageContainer()
{
	delete[]image;
}

// wipe the loaded image
void ImageContainer::reset()
{
	delete[]image;
	image = NULL;
	mimetype = "";
	imagelength = 0;
}

// send image to client
void ImageContainer::display(Socket * s)
{
#ifdef DGDEBUG
	std::cout << "Displaying custom image file" << std::endl;
	std::cout << "mimetype: " << mimetype << std::endl;
#endif
	s->writeString("Content-type: ");
	s->writeString(mimetype.toCharArray());
	s->writeString("\n\n");

	if (!s->writeToSocket(image, imagelength, 0, s->getTimeout()))
		throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
}

// read image from file
bool ImageContainer::read(const char *filename)
{
	String temp(filename);
	temp.toLower();

	if (temp.endsWith(".jpg") || temp.endsWith(".jpeg") || temp.endsWith(".jpe")) {
		mimetype = "image/jpg";
	}
	else if (temp.endsWith("png"))
		mimetype = "image/png";
	else if (temp.endsWith("swf"))
		mimetype = "application/x-shockwave-flash";
	else{
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
			if (!is_daemonised)
				std::cerr << "Error reading custom image file: " << filename << std::endl;
			syslog(LOG_ERR, "%s", "Error reading custom image file.");
			return false;
		}
	} else {
		if (!is_daemonised)
			std::cerr << "Error reading custom image file: " << filename << std::endl;
		syslog(LOG_ERR, "%s", "Error reading custom image file.");
		return false;
	}
	imagefile.close();
//    #ifdef DGDEBUG
//      for (long int i = 0; i < imagelength; i++)
//          printf("Image byte content: %x\n", image[i]);
//    #endif
	return true;
}
