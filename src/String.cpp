// String - guess what: it's a string class!

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "String.hpp"
#include "md5.hpp"

#if defined(__GNUC__) && __GNUC__ < 3 && __GNUC_MINOR__ < 96
#warning "Using strstream instead of sstream"
#include <strstream>
#else
#include <sstream>
#endif

#include <cstdlib>
#include <cstring>

// construct string representations of ints/longs
#if defined(__GNUC__) && __GNUC__ < 3 && __GNUC_MINOR__ < 96
String::String(const int num)
{
	std::ostrstream buf;
	buf << num << std::ends;
	*this = buf.str();  // with side effect: it calls buf.freeze()
}
String::String(const long num)
{
	std::ostrstream buf;
	buf << num << std::ends;
	*this = buf.str();
}
String::String(const unsigned int num)
{
	std::ostrstream buf;
	buf << num << std::ends;
	*this = buf.str();
}
String::String(const long unsigned int num)
{
	std::ostrstream buf;
	buf << num << std::ends;
	*this = buf.str();
}
# ifndef OFFT_COLLISION
// If large file support is not enabled (and possibly even if it is),
// the type of off_t may be a typedef of a type for which we already
// have a constructor. In that case, don't define one which takes an
// off_t, or we get compiler errors.
String::String(const off_t num)
{
	std::ostrstream buf;
	buf << num << std::ends;
	*this = buf.str();
}
# endif
#else
String::String(const int num)
{
	std::stringstream buf;
	buf << num << std::ends;
	// std::string can contain a NULL byte within the counted length
	// - this happens here. Add a byte to the length when allocating
	// the buffer it's going to go into (to account for the appended
	// NULL), but subtract one when updating our idea of what the string
	// length is, since it counts the NULL byte in the stringstream's
	// own buffer.
	int l = buf.str().length();
	char* data = new char[l+1];
	buf >> data;
	*this = data;
	delete[] data;
}
String::String(const long num)
{
	std::stringstream buf;
	buf << num << std::ends;
	int l = buf.str().length();
	char* data = new char[l+1];
	buf >> data;
	*this = data;
	delete[] data;
}
String::String(const unsigned int num)
{
	std::stringstream buf;
	buf << num << std::ends;
	int l = buf.str().length();
	char* data = new char[l+1];
	buf >> data;
	*this = data;
	delete[] data;
}
String::String(const long unsigned num)
{
	std::stringstream buf;
	buf << num << std::ends;
	int l = buf.str().length();
	char* data = new char[l+1];
	buf >> data;
	*this = data;
	delete[] data;
}
# ifndef OFFT_COLLISION
// If large file support is not enabled (and possibly even if it is),
// the type of off_t may be a typedef of a type for which we already
// have a constructor. In that case, don't define one which takes an
// off_t, or we get compiler errors.
String::String(const off_t num)
{
	std::stringstream buf;
	buf << num << std::ends;
	int l = buf.str().length();
	char* data = new char[l+1];
	buf >> data;
	*this = data;
	delete[] data;
}
# endif
#endif

void String::replaceall(const char *what, const char *with)
{
	std::string::size_type pos = 0;
	size_t whatlen = strlen(what);
	size_t withlen = strlen(with);
	while ((pos = this->find(what, pos)) != std::string::npos)
	{
		// replace charactrs in original string
		this->replace(pos, whatlen, with);
		// increment search position
		pos += withlen;
	}
}

// string-to-off_t conversion
// This is horrible, horrible code, but the best I can come up with
// which will work in both 32 and 64-bit file offset modes. :(
off_t String::toOffset()
{
	if (this->length() == 0)
		return 0;
	off_t t = 0;

	this->removeWhiteSpace();

#if defined(_FILE_OFFSET_BITS) && (_FILE_OFFSET_BITS == 64)
	sscanf(this->c_str(), "%lld", &t);
#else
	sscanf(this->c_str(), "%ld", &t);
#endif

	return t;
}

// string-to-integer conversion
int String::toInteger()
{
	if (this->length() == 0) {
		return 0;
	}
	return (atoi(this->c_str()));
}

// string-to-long-int conversion
long int String::toLong()
{
	if (this->length() == 0) {
		return 0;
	}
	return (atol(this->c_str()));
}

// return integer from hex string
int String::hexToInteger() {
	int n = 0;         // position in string
	int m = 0;         // position in digit[] to shift
	int count;         // loop index
	int intValue = 0;  // integer value of hex string
	int digit[5];      // hold values to convert
	while (n < 4) {
		if ((*this)[n]=='\0')
			break;
		if ((*this)[n] > '0' && (*this)[n] < '9' )
			digit[n] = (*this)[n] & 0x0f;
		else if (((*this)[n] >='a' && (*this)[n] <= 'f') || ((*this)[n] >='A' && (*this)[n] <= 'F'))
			digit[n] = ((*this)[n] & 0x0f) + 9;
		else break;
		n++;
	}
	count = n;
	m = n - 1;
	n = 0;
	while(n < count) {
		// digit[n] is value of hex digit at position n
		// (m << 2) is the number of positions to shift
		// OR the bits into return value
		intValue = intValue | (digit[n] << (m << 2));
		m--;
		n++;
	}
	return (intValue);
}

// case conversions
void String::toLower()
{
	unsigned int l = this->length();
	char* c = new char[l + 1];
	const char* d = this->c_str();
	for (unsigned int i = 0; i < l; i++) {
		c[i] = tolower(d[i]);
	}
	*this = String(c, l);
	delete[] c;
}

void String::toUpper()
{
	unsigned int l = this->length();
	char* c = new char[l + 1];
	const char* d = this->c_str();
	for (unsigned int i = 0; i < l; i++) {
		c[i] = toupper(d[i]);
	}
	*this = String(c, l);
	delete[] c;
}

// decode %xx to individual characters (checkme: i'm sure this is duplicated elsewhere...)
void String::hexDecode()
{
	if (this->length() < 3)
		return;
	char *temp = new char[this->length() + 1];
	const char *t = this->c_str();
	unsigned char c;
	unsigned char c1;
	unsigned char c2;
	unsigned char c3;
	char hexval[5] = "0x";  // Initializes a "hexadecimal string"
	hexval[4] = '\0';
	char *ptr;  // pointer required by strtol
	unsigned int j = 0;
	unsigned int end = this->length() - 2;
	unsigned int i, k;
	for (i = 0; i < end;) {
		c1 = t[i];
		c2 = t[i + 1];
		c3 = t[i + 2];
		if (c1 == '%' && (((c2 >= '0') && (c2 <= '9')) || ((c2 >= 'a') && (c2 <= 'f')) || ((c2 >= 'A') && (c2 <= 'F'))) && (((c3 >= '0') && (c3 <= '9')) || ((c3 >= 'a') && (c3 <= 'f')) || ((c3 >= 'A') && (c3 <= 'F')))) {
			hexval[2] = c2;
			hexval[3] = c3;
			c = (unsigned char) strtol(hexval, &ptr, 0);
			i += 3;
		} else {
			c = c1;
			i++;
		}
		temp[j++] = c;
	}
	k = this->length();
	for (; i < k; i++) {
		temp[j++] = t[i];  // copy last 2 bytes if any//
	}
	temp[j] = '\0';
	(*this) = String(temp, j);
	delete[]temp;
}

// does this string start with the given text?
bool String::startsWith(const String& s) const
{
	return (strncmp(this->c_str(), s.c_str(), s.length()) == 0);
}

// does this string end with the given text?
bool String::endsWith(const String& s) const
{
	if (s.length() > this->length()) {
		return false;
	}
	if (!strncmp((this->c_str() + this->length() - s.length()), s.c_str(), s.length())) {
		return true;
	}
	return false;
}

// does this string start with the given text after conversion to lowercase?
// (pass the search string in in lowercase; only the text being searched
// is converted)
bool String::startsWithLower(const String& s) const
{
	for (unsigned int i = 0; i < s.length(); i++) {
		if (tolower((*this)[i]) != s[i])
			return false;
	}
	return true;
}

// find the position of the given substring within the string
int String::indexOf(const char *s) const
{
	size_type i = this->find(s);
	if (i != std::string::npos)
		return i;
	return -1;
}

// does this string contain given substring?
bool String::contains(const char *s) const
{
	if (indexOf(s) != -1) {
		return true;
	}
	return false;
}

// grab the part of the string that follows the first occurrence of given text
String String::after(const char *bs) const
{
	size_type i = this->find(bs);
	if (i == std::string::npos)
		return "";
	return this->substr(i + strlen(bs));
}

// grab the part of the string that precedes the first occurrence of given text
String String::before(const char *bs) const
{
	size_type i = this->find(bs);
	if (i == std::string::npos)
		return "";
	return this->substr(0, i);
}

// remove characters from end/beginning
void String::chop()
{
	*this = this->substr(0, this->length() - 1);
}
void String::lop()
{
	*this = this->substr(1);
}

// remove leading & trailing whitespace
void String::removeWhiteSpace()
{
	size_type start = this->find_first_not_of(" \t\r\n");
	if (start == std::string::npos)
		start = 0;
	size_type end = this->find_last_not_of(" \t\r\n");
	if (end == std::string::npos)
		end = this->length() - 1;
	*this = this->substr(start, (end - start)+1);
}

// remove protocol specifier
void String::removePTP()
{
	if (this->startsWith("http://") || this->startsWith("https://")
		|| this->startsWith("ftp://"))
	{
		*this = this->after("://");
	}
}
// get hostname from string as url
String String::getHostname()
{
    String hostname;
    hostname = this->substr(0);
    if (hostname.contains("://"))
        hostname = hostname.after("://");
	if (hostname.contains("/"))
		hostname = hostname.before("/");
	if (hostname.contains("@")) // Contains a username:password combo
	    hostname = hostname.after("@");
	return hostname;
}

// limit string to given length
int String::limitLength(unsigned int l)
{
	*this = this->substr(0, l);
	return this->length();
}

// remove repeated occurrences of given character
void String::removeMultiChar(unsigned char c)
{
	std::string temp;
	unsigned char t;
	bool wasslash = false;
	unsigned int l = this->length();
	for (unsigned int i = 0; i < l; i++) {
		t = (*this)[i];
		if (t != c) {
			// we didn't find the character - copy what we did find,
			// and clear repetition flag
			temp += t;
			wasslash = false;
			continue;
		}
		// we found the character
		if (wasslash) {
			// we found it repeated - don't copy it again
			continue;
		}
		// we found the character, without repetition flag set
		// - copy only first occurrence & set repetition flag
		wasslash = true;
		temp += t;
	}
	*this = temp;
}

// tidy up slashes, trailing dots, etc. in file paths
void String::realPath()
{
	if (this->length() < 3) {
		return;
	}
	char *temp = new char[this->length() + 1];
	unsigned char b, c, d;
	unsigned int offset = 0, l = this->length();
	for (unsigned int i = 0; i < l; i++) {
		b = (*this)[i];
		if (b == '/') {
			if ((*this)[i + 1] == '/') {	// ignore multiple slashes
				continue;
			}
		}
		if (b == '.') {
			c = (*this)[i + 1];
			if (c == '\0' || c == '/') {
				continue;  // ignore just dot
			}
			if (c == '.') {
				d = (*this)[i + 2];
				if (d == '\0' || d == '/' || d == '\\') {
					if (offset > 0) {
						offset--;
					}
					while (offset > 0) {
						if (temp[--offset] == '/') {
							break;
						}
						if (temp[offset] == '\\') {
							break;
						}
					}
					i++;
					continue;
				}
			}
		}
		temp[offset++] = b;
	}
	temp[offset] = '\0';
	*this = temp;
	delete[] temp;
}

// *
// *
// * Hashing functions
// *
// *

String String::md5(const char *salt)
{
	String newValue(*this);
	newValue += salt;
	return newValue.md5();
}

String String::md5()
{
	char *md5array = new char[16];
	char *buf = new char[16];
	int i;

	String ret;

	md5_buffer(this->c_str(), (size_t) this->length(), md5array);

	for (i = 0; i < 16; i++) {
		sprintf(buf, "%02X", (unsigned char) (md5array[i]));
		ret += buf;
	}

	delete[]md5array;
	delete[]buf;

	return ret;
}
