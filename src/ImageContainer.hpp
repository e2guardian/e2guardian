// ImageContainer - container class for custom banned image

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_IMAGECONTAINER
#define __HPP_IMAGECONTAINER


// INCLUDES
#include "Socket.hpp"
#include "String.hpp"

class ImageContainer
{
public:
	ImageContainer();
	~ImageContainer();
	
	// wipe loaded image
	void reset();
	// read image from file
	bool read(const char *filename);
	// send image to client
	void display(Socket * s);

private:
	long int imagelength;
	String mimetype;
	char *image;
};
#endif
