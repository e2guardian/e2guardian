// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "String.hpp"
#include "OptionContainer.hpp"
#include "NaughtyFilter.hpp"
#include "RegExp.hpp"
#include "ListContainer.hpp"

#include <cstring>
#include <syslog.h>
#include <algorithm>


// GLOBALS 

extern OptionContainer o;

#ifdef HAVE_PCRE
extern RegExp absurl_re, relurl_re;
#endif


// DECLARATIONS

// category list entry class - stores category index & weight of all phrases
// found so far that fall under this category. also includes a less-than
// operator so that the STL sort algorithm can be applied to lists of these.
class listent {
public:
	listent():weight(0), string("") {};
	listent(const int& w, String& s) {
		weight = w;
		string = s;
	};
	int weight;
	String string;
	int operator < (const listent &a) const {
		// sort in descending order of score
		return weight > a.weight ? 1 : 0;
	};
};


// IMPLEMENTATION

// constructor - set up defaults
NaughtyFilter::NaughtyFilter()
:	isItNaughty(false), isException(false), usedisplaycats(false), blocktype(0), store(false), naughtiness(0)
{
}

void NaughtyFilter::reset()
{
	isItNaughty = false;
	isException = false;
	whatIsNaughty = "";
	whatIsNaughtyLog = "";
	whatIsNaughtyCategories = "";
	usedisplaycats = false;
	blocktype = 0;
	store = false;
	naughtiness = 0;
}

// check the given document body for banned, weighted, and exception phrases (and PICS, and regexes, &c.)
// also used for scanning search terms, which causes various features - PICS, META/TITLE extraction, etc. - to be disabled
void NaughtyFilter::checkme(const char *rawbody, off_t rawbodylen, const String *url,
	const String *domain, unsigned int filtergroup, unsigned int phraselist, int limit, bool searchterms)
{
#ifdef DGDEBUG
	if (searchterms)
		std::cout << "Content flagged as search terms - disabling PICS, hex decoding, META/TITLE extraction & HTML removal" << std::endl;
#endif

	// check PICS now - not dependent on case, hex decoding, etc.
	// as only sites which play by the rules will self-rate
	if (!searchterms && (*o.fg[filtergroup]).enable_PICS) {
#ifdef DGDEBUG
		std::cout << "PICS is enabled" << std::endl;
#endif
		checkPICS(rawbody, filtergroup);
		if (isItNaughty)
			return;  // Well there is no point in continuing is there?
	}
	
	if (o.fg[filtergroup]->weighted_phrase_mode == 0)
	{
#ifdef DGDEBUG
		std::cout << "Weighted phrase mode 0 - not going any further." << std::endl;
#endif
		return;
	}
	
	// hex-decoded data (not case converted)
	off_t hexdecodedlen = rawbodylen;
	const char *hexdecoded = rawbody;

	unsigned char c;

	// Hex decode content if desired
	// Do this now, as it's not especially case-sensitive,
	// and the case alteration should modify case post-decoding
	// Search terms are already hex decoded, as they need to be to strip URL decoding
	if (!searchterms && o.hex_decode_content) {  // Mod suggested by AFN Tue 8th April 2003
#ifdef DGDEBUG
		std::cout << "Hex decoding is enabled" << std::endl;
#endif
		char *hexdecoded_buf = new char[rawbodylen + 128 + 1];
		memset(hexdecoded_buf, 0, rawbodylen + 128 + 1);
		unsigned char c1;
		unsigned char c2;
		unsigned char c3;
		char hexval[5] = "0x";  // Initializes a "hexadecimal string"
		hexval[4] = '\0';
		char *ptr;  // pointer required by strtol

		// make a copy of the escaped document char by char
		off_t i = 0;
		off_t j = 0;
		while (i < rawbodylen - 3) {  // we lose 3 bytes but what the hell..
			c1 = rawbody[i];
			c2 = rawbody[i + 1];
			c3 = rawbody[i + 2];
			if (c1 == '%' && (((c2 >= '0') && (c2 <= '9')) || ((c2 >= 'a') && (c2 <= 'f')) || ((c2 >= 'A') && (c2 <= 'F')))
				&& (((c3 >= '0') && (c3 <= '9')) || ((c3 >= 'a') && (c3 <= 'f')) || ((c3 >= 'A') && (c3 <= 'F'))))
			{
				hexval[2] = c2;
				hexval[3] = c3;
				c = (unsigned char) strtol(hexval, &ptr, 0);
				i += 3;
			} else {
				c = c1;
				i++;
			}
			hexdecoded_buf[j] = c;
			j++;
		}
		// copy any remaining bytes
		while (i < rawbodylen) {
			hexdecoded_buf[j++] = rawbody[i++];
		} 
		hexdecoded_buf[j] = '\0';
		hexdecodedlen = j;
		hexdecoded = hexdecoded_buf;
	}

	// scan twice, with & without case conversion (if desired) - aids support for exotic char encodings
	// TODO: move META/title sentinel location outside this loop, as they are not case sensitive operations
	bool preserve_case = o.preserve_case;
	if (o.preserve_case == 2) {
		// scanning twice *is* desired
		// first time round the loop, don't preserve case (non-exotic encodings)
#ifdef DGDEBUG
		std::cout << "Filtering with/without case preservation is enabled" << std::endl;
#endif
		preserve_case = false;
	}
	
	// Store for the lowercase (maybe) data
	// The extra 128 is used for various speed tricks to
	// squeeze as much speed as possible.
	char* bodylc = new char[hexdecodedlen + 128 + 1];
	memset(bodylc, 0, hexdecodedlen + 128 + 1);
	
	// Store for the tag-stripped data
	// Don't bother tag stripping search terms
	char* bodynohtml = NULL;
	if (!searchterms && (o.phrase_filter_mode == 1 || o.phrase_filter_mode == 2))
	{
		bodynohtml = new char[hexdecodedlen + 128 + 1];
		memset(bodynohtml, 0, hexdecodedlen + 128 + 1);
	}
	
	for (int loop = 0; loop < (o.preserve_case == 2 ? 2 : 1); loop++) {
#ifdef DGDEBUG
		std::cout << "Preserve case: " << preserve_case << std::endl;
#endif

		off_t i, j;
#ifdef DGDEBUG
		if (searchterms || o.phrase_filter_mode == 0 || o.phrase_filter_mode == 2 || o.phrase_filter_mode == 3)
			std::cout << "Raw content needed" << std::endl;
#endif
		// use the one that's been hex decoded, but not stripped
		// make a copy of the document lowercase char by char
		if (preserve_case) {
			for (i = 0; i < hexdecodedlen; i++) {
				c = hexdecoded[i];
				if (c == 13 || c == 9 || c == 10) {
					c = 32;  // convert all whitespace to a space
				}
				bodylc[i] = c;
			}
		} else {
#ifdef DGDEBUG
			std::cout << "Not preserving case of raw content" << std::endl;
#endif
			for (i = 0; i < hexdecodedlen; i++) {
				c = hexdecoded[i];
				if (c >= 'A' && c <= 'Z') {
					c = 'a' + c - 'A';
				}
				else if (c >= 192 && c <= 221) {  // for accented chars
					c += 32;  // 224 + c - 192
				} else {
					if (c == 13 || c == 9 || c == 10) {
						c = 32;  // convert all whitespace to a space
					}
				}
				bodylc[i] = c;
			}
		}

		// filter meta tags & title only
		// based on idea from Nicolas Peyrussie
		if(!searchterms && (o.phrase_filter_mode == 3)) {
#ifdef DGDEBUG
			std::cout << "Filtering META/title" << std::endl;
#endif
			bool addit = false;  // flag if we should copy this char to filtered version
			bool needcheck = false;  // flag if we actually find anything worth filtering
			off_t bodymetalen;
		
			// find </head> or <body> as end of search range
			char* endhead = strstr(bodylc, "</head");
#ifdef DGDEBUG
			if (endhead != NULL)
				std::cout<<"Found '</head', limiting search range"<<std::endl;
#endif
			if (endhead == NULL) {
				endhead = strstr(bodylc, "<body");
#ifdef DGDEBUG
				if (endhead != NULL)
					std::cout<<"Found '<body', limiting search range"<<std::endl;
#endif
			}

			// if case preserved, also look for uppercase versions
			if (preserve_case and (endhead == NULL)) {
				endhead = strstr(bodylc, "</HEAD");
#ifdef DGDEBUG
				if (endhead != NULL)
					std::cout<<"Found '</HEAD', limiting search range"<<std::endl;
#endif
				if (endhead == NULL) {
					endhead = strstr(bodylc, "<BODY");
#ifdef DGDEBUG
					if (endhead != NULL)
						std::cout<<"Found '<BODY', limiting search range"<<std::endl;
#endif
				}
			}

			if (endhead == NULL)
				endhead = bodylc+hexdecodedlen;

			char* bodymeta = new char[(endhead - bodylc) + 128 + 1];
			memset(bodymeta, 0, (endhead - bodylc) + 128 + 1);

			// initialisation for removal of duplicate non-alphanumeric characters
			j = 1;
			bodymeta[0] = 32;

			for (i = 0; i < (endhead - bodylc) - 7; i++) {
				c = bodylc[i];
				// are we at the start of a tag?
				if ((!addit) && (c == '<')) {
					if ((strncmp(bodylc+i+1, "meta", 4) == 0) or (preserve_case and (strncmp(bodylc+i+1, "META", 4) == 0))) {
#ifdef DGDEBUG
						std::cout << "Found META" << std::endl;
#endif
						// start adding data to the check buffer
						addit = true;
						needcheck = true;
						// skip 'meta '
						i += 6;
						c = bodylc[i];
					}
					// are we at the start of a title tag?
					else if ((strncmp(bodylc+i+1, "title", 5) == 0) or (preserve_case and (strncmp(bodylc+i+1, "TITLE", 5) == 0))) {
#ifdef DGDEBUG
						std::cout << "Found TITLE" << std::endl;
#endif
						// start adding data to the check buffer
						addit = true;
						needcheck = true;
						// skip 'title>'
						i += 7;
						c = bodylc[i];
					}
				}
				// meta tags end at a >
				// title tags end at the next < (opening of </title>)
				if (addit && ((c == '>') || (c == '<'))) {
					// stop ading data
					addit = false;
					// add a space before the next word in the check buffer
					bodymeta[j++] = 32;
				}
			
				if (addit) {
					// if we're in "record" mode (i.e. inside a title/metatag), strip certain characters out
					// of the data (to sanitise metatags & aid filtering of titles)
					if ( c== ',' || c == '=' || c == '"' || c  == '\''
						|| c == '(' || c == ')' || c == '.')
					{
						// replace with a space
						c = 32;
					}
					// don't bother duplicating spaces
					if ((c != 32) || (c == 32 && (bodymeta[j-1] != 32))) {
						bodymeta[j++] = c;  // copy it to the filtered copy
					}
				}
			}
			if (needcheck) {
				bodymeta[j++] = '\0';
#ifdef DGDEBUG
				std::cout << bodymeta << std::endl;
#endif
				bodymetalen = j;
				checkphrase(bodymeta, bodymetalen, NULL, NULL, filtergroup, phraselist, limit, searchterms);
			}
#ifdef DGDEBUG
			else
				std::cout<<"Nothing to filter"<<std::endl;
#endif

			delete[] bodymeta;
			// surely the intention is to search *only* meta/title, so always exit
			delete[] bodylc;
			delete[] bodynohtml;
			if (hexdecoded != rawbody)
				delete[]hexdecoded;
			return;
		}

		if (searchterms || o.phrase_filter_mode == 0 || o.phrase_filter_mode == 2) {
#ifdef DGDEBUG
			std::cout << "Checking raw content" << std::endl;
#endif
			// check unstripped content
			checkphrase(bodylc, hexdecodedlen, url, domain, filtergroup, phraselist, limit, searchterms);
			if (isItNaughty || isException) {
				delete[]bodylc;
				delete[] bodynohtml;
				if (hexdecoded != rawbody)
					delete[]hexdecoded;
				return;  // Well there is no point in continuing is there?
			}
		}

		if (searchterms || o.phrase_filter_mode == 0) {
			delete[]bodylc;
			delete[] bodynohtml;
			if (hexdecoded != rawbody)
				delete[]hexdecoded;
			return;  // only doing raw mode filtering
		}

		// if we fell through to here, use the one that's been hex decoded AND stripped
		// Strip HTML
#ifdef DGDEBUG
		std::cout << "\"Smart\" filtering is enabled" << std::endl;
#endif
		// we need this extra byte *
		bool inhtml = false;  // to flag if our pointer is within a html <>
		bool addit;  // flag if we should copy this char to filtered version
		j = 1;
		bodynohtml[0] = 32;  // * for this
		for (off_t i = 0; i < hexdecodedlen; i++) {
			addit = true;
			c = bodylc[i];
			if (c == '<') {
				inhtml = true;  // flag we are inside a html <>
			}
			if (c == '>') {	// flag we have just left a html <>
				inhtml = false;
				c = 32;
			}
			if (inhtml) {
				addit = false;
			}
			if (c == 32) {
				if (bodynohtml[j - 1] == 32) {	// * and this
					addit = false;
				}
			}
			if (addit) {	// if it passed the filters
				bodynohtml[j++] = c;  // copy it to the filtered copy
			}
		}
#ifdef DGDEBUG
		std::cout << "Checking smart content" << std::endl;
#endif
		checkphrase(bodynohtml, j - 1, NULL, NULL, filtergroup, phraselist, limit, searchterms);

		// second time round the case loop (if there is a second time),
		// do preserve case (exotic encodings)
		preserve_case = true;
	}
	delete[]bodylc;
	delete[]bodynohtml;
	if (hexdecoded != rawbody)
		delete[]hexdecoded;
}

// check the phrase lists
void NaughtyFilter::checkphrase(char *file, off_t filelen, const String *url, const String *domain,
	unsigned int filtergroup, unsigned int phraselist, int limit, bool searchterms)
{
	int weighting = 0;
	int cat;
	std::string weightedphrase;
	
	// checkme: translate this?
	String currcat("Embedded URLs");

	// found categories list & reusable iterators
	std::map<int, listent> listcategories;

	// check for embedded references to banned sites/URLs.
	// have regexes that check for URLs in pages (look for attributes (src, href, javascript location)
	// or look for protocol strings (in which case, incl. ftp)?) and extract them.
	// then check the extracted list against the banned site/URL lists.
	// ADs category lists do not want to add to the possibility of a site being banned.
	// Exception lists are not checked.
	// Do not do full-blown category retrieval/duplicate checking; simply add the
	// "Embedded URLs" category.
	// Put a warning next to the option in the config file that this will take lots of CPU.
	// Support phrase mode 1/2 distinction (duplicate sites/URLs).
	// Have weight configurable per filter group, not globally or with a list directive - 
	//   a weight of 0 will disable the option, effectively making this functionality per-FG itself.

	// todo: if checkphrase is passed the domain & existing URL, it can create full URLs from relative ones.
	// if a src/href URL starts with a /, append it to the domain; otherwise, append it to the existing URL.
	// chop off anything after a ?, run through realPath, then put through the URL lists.

#ifdef HAVE_PCRE
	// if weighted phrases are enabled, and we have been passed a URL and domain, and embedded URL checking is enabled...
	// then check for embedded URLs!
	if (url != NULL && o.fg[filtergroup]->embedded_url_weight > 0) {
		std::map<int, listent>::iterator ourcat;
		bool catinited = false;
		std::map<String, unsigned int> found;
		std::map<String, unsigned int>::iterator founditem;

		String u;
		char* j;

		// check for absolute URLs
		if (absurl_re.match(file)) {
			// each match generates 2 results (because of the brackets in the regex), we're only interested in the first
#ifdef DGDEBUG
			std::cout << "Found " << absurl_re.numberOfMatches()/2 << " absolute URLs:" << std::endl;
#endif
			for (int i = 0; i < absurl_re.numberOfMatches(); i+=2) {
				// chop off quotes
				u = absurl_re.result(i);
				u = u.subString(1,u.length()-2);
#ifdef DGDEBUG
				std::cout << u << std::endl;
#endif
				if ((((j = o.fg[filtergroup]->inBannedSiteList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_site_list]->lastcategory.contains("ADs")))
					|| (((j = o.fg[filtergroup]->inBannedURLList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_url_list]->lastcategory.contains("ADs"))))
				{
					// duplicate checking
					// checkme: this should really be being done *before* we search the lists.
					// but because inBanned* methods do some cleaning up of their own, we don't know the form to check against.
					// we actually want these cleanups do be done before passing to inBanned*/inException* - this would
					// speed up ConnectionHandler a bit too.
					founditem = found.find(j);
					if ((o.fg[filtergroup]->weighted_phrase_mode == 2) && (founditem != found.end())) {
						founditem->second++;
					} else {
						// add the site to the found phrases list
						found[j] = 1;
						if (weightedphrase.length() == 0)
							weightedphrase = "[";
						else
							weightedphrase += " ";
						weightedphrase += j;
						if (!catinited) {
							listcategories[-1] = listent(o.fg[filtergroup]->embedded_url_weight,currcat);
							ourcat = listcategories.find(-1);
							catinited = true;
						} else
							ourcat->second.weight += o.fg[filtergroup]->embedded_url_weight;
					}
				}
			}
		}

		found.clear();

		// check for relative URLs
		if (relurl_re.match(file)) {
			// we don't want any parameters on the end of the current URL, since we append to it directly
			// when forming absolute URLs from relative ones. we do want a / on the end, too.
			String currurl(*url);
			if (currurl.contains("?"))
				currurl = currurl.before("?");
			if (currurl[currurl.length()-1] != '/')
				currurl += "/";

			// each match generates 2 results (because of the brackets in the regex), we're only interested in the first
#ifdef DGDEBUG
			std::cout << "Found " << relurl_re.numberOfMatches()/2 << " relative URLs:" << std::endl;
#endif
			for (int i = 0; i < relurl_re.numberOfMatches(); i+=2) {
				u = relurl_re.result(i);
				
				// can't find a way to negate submatches in PCRE, so it is entirely possible
				// that some absolute URLs have made their way into this list. we don't want them.
				if (u.contains("://"))
					continue;

#ifdef DGDEBUG
				std::cout << u << std::endl;
#endif
				// remove src/href & quotes
				u = u.after("=");
				u.removeWhiteSpace();
				u = u.subString(1,u.length()-2);
				
				// create absolute URL
				if (u[0] == '/')
					u = (*domain) + u;
				else
					u = currurl + u;
#ifdef DGDEBUG
				std::cout << "absolute form: " << u << std::endl;
#endif
				if ((((j = o.fg[filtergroup]->inBannedSiteList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_site_list]->lastcategory.contains("ADs")))
					|| (((j = o.fg[filtergroup]->inBannedURLList(u)) != NULL) && !(o.lm.l[o.fg[filtergroup]->banned_url_list]->lastcategory.contains("ADs"))))
				{
					// duplicate checking
					// checkme: this should really be being done *before* we search the lists.
					// but because inBanned* methods do some cleaning up of their own, we don't know the form to check against.
					// we actually want these cleanups do be done before passing to inBanned*/inException* - this would
					// speed up ConnectionHandler a bit too.
					founditem = found.find(j);
					if ((o.fg[filtergroup]->weighted_phrase_mode == 2) && (founditem != found.end())) {
						founditem->second++;
					} else {
						// add the site to the found phrases list
						found[j] = 1;
						if (weightedphrase.length() == 0)
							weightedphrase = "[";
						else
							weightedphrase += " ";
						weightedphrase += j;
						if (!catinited) {
							listcategories[-1] = listent(o.fg[filtergroup]->embedded_url_weight,currcat);
							ourcat = listcategories.find(-1);
							catinited = true;
						} else
							ourcat->second.weight += o.fg[filtergroup]->embedded_url_weight;
					}
				}
			}
		}
		if (catinited) {
			weighting = ourcat->second.weight;
			weightedphrase += "]";
#ifdef DGDEBUG
			std::cout << weightedphrase << std::endl;
			std::cout << "score from embedded URLs: " << ourcat->second.weight << std::endl;
#endif
		}
	}
#endif

	std::string bannedphrase;
	std::string exceptionphrase;
	String bannedcategory;
	int type, index, weight, time;
	bool allcmatched = true, bannedcombi = false;
	std::string s1;

	// this line here searches for phrases contained in the list - the rest of the code is all sorting
	// through it to find the categories, weightings, types etc. of what has actually been found.
	std::map<std::string, std::pair<unsigned int, int> > found;
	o.lm.l[phraselist]->graphSearch(found, file, filelen);

	// cache reusable iterators
	std::map<std::string, std::pair<unsigned int, int> >::iterator foundend = found.end();
	std::map<std::string, std::pair<unsigned int, int> >::iterator foundcurrent;

	// look for combinations first
	//if banned must wait for exception later
	std::string combifound;
	std::string combisofar;

	std::vector<int>::iterator combicurrent = o.lm.l[phraselist]->combilist.begin();
	std::map<int, listent>::iterator catcurrent;
	int lowest_occurrences = 0;

	while (combicurrent != o.lm.l[phraselist]->combilist.end()) {
		// Grab the current combination phrase part
		index = *combicurrent;
		// Do stuff if what we have is an end marker (end of one list of parts)
		if (index == -2) {
			// Were all the parts in this combination matched?
			if (allcmatched) {
				type = *(++combicurrent);
				// check this time limit against the list of time limits
				time = *(++combicurrent);
				if (not (o.lm.l[phraselist]->checkTimeAtD(time))) {
					// nope - so don't take any notice of it
#ifdef DGDEBUG
					combicurrent++;
					cat = (*++combicurrent);
					std::cout << "Ignoring combi phrase based on time limits: " << combisofar << "; "
						<< o.lm.l[phraselist]->getListCategoryAtD(cat) << std::endl;
#else
					combicurrent += 2;
#endif
					combisofar = "";
				}
				else if (type == -1) {	// combination exception
					isItNaughty = false;
					isException = true;
					// Combination exception phrase found:
					// Combination exception search term found:
					whatIsNaughtyLog = o.language_list.getTranslation(searchterms ? 456 : 605);
					whatIsNaughtyLog += combisofar;
					whatIsNaughty = "";
					++combicurrent;
					cat = *(++combicurrent);
					whatIsNaughtyCategories = o.lm.l[phraselist]->getListCategoryAtD(cat);
					return;
				}
				else if (type == 1) {	// combination weighting
					weight = *(++combicurrent);
					weighting += weight * (o.fg[filtergroup]->weighted_phrase_mode == 2 ? 1 : lowest_occurrences);
					if (weight > 0) {
						cat = *(++combicurrent);
						//category index -1 indicates an uncategorised list
						if (cat >= 0) {
							//don't output duplicate categories
							catcurrent = listcategories.find(cat);
							if (catcurrent != listcategories.end()) {
								catcurrent->second.weight += weight * (o.fg[filtergroup]->weighted_phrase_mode == 2 ? 1 : lowest_occurrences);
							} else {
								currcat = o.lm.l[phraselist]->getListCategoryAtD(cat);
								listcategories[cat] = listent(weight,currcat);
							}
						}
					} else {
						// skip past category for negatively weighted phrases
						combicurrent++;
					}
					if (weightedphrase.length() > 0) {
						weightedphrase += "+";
					}
					weightedphrase += "(";
					if (weight < 0) {
						weightedphrase += "-" + combisofar;
					} else {
						weightedphrase += combisofar;
					}
#ifdef DGDEBUG
					std::cout << "found combi weighted phrase ("<< o.fg[filtergroup]->weighted_phrase_mode << "): "
						<< combisofar << " x" << lowest_occurrences << " (per phrase: "
						<< weight << ", calculated: "
						<< (weight * (o.fg[filtergroup]->weighted_phrase_mode == 2 ? 1 : lowest_occurrences)) << ")"
						<< std::endl;
#endif

					weightedphrase += ")";
					combisofar = "";
				}
				else if (type == 0) {	// combination banned
					bannedcombi = true;
					combifound += "(" + combisofar + ")";
					combisofar = "";
					combicurrent += 2;
					cat = *(combicurrent);
					bannedcategory = o.lm.l[phraselist]->getListCategoryAtD(cat);
				}
			} else {
				// We had an end marker, but not all the parts so far were matched.
				// Reset the match flag ready for the next chain, and advance to its first part.
				allcmatched = true;
				combicurrent += 4;
				lowest_occurrences = 0;
			}
		} else {
			// We didn't get an end marker - just an individual part.
			// If all parts in the current chain have been matched so far, look for this one as well.
			if (allcmatched) {
				s1 =o.lm.l[phraselist]->getItemAtInt(index);
				if ((foundcurrent = found.find(s1)) == foundend) {
					allcmatched = false;
					combisofar = "";
				} else {
					if (combisofar.length() > 0) {
						combisofar += ", ";
					}
					combisofar += s1;
					// also track lowest number of times any one part occurs in the text
					// as this will correspond to the number of times the whole chain occurs
					if ((lowest_occurrences == 0) || (lowest_occurrences > foundcurrent->second.second)) {
						lowest_occurrences = foundcurrent->second.second;
					}
				}
			}
		}
		// Advance to the next part in the current chain
		combicurrent++;
	}

	// even if we already found a combi ban, we must still wait; there may be non-combi exceptions to follow

	// now check non-combi phrases
	foundcurrent = found.begin();
	while (foundcurrent != foundend) {
		// check time for current phrase
		if (not o.lm.l[phraselist]->checkTimeAt(foundcurrent->second.first)) {
#ifdef DGDEBUG
			std::cout << "Ignoring phrase based on time limits: "
				<< foundcurrent->first << ", "
				<< o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first) << std::endl;
#endif
			foundcurrent++;
			continue;
		}
		// 0=banned, 1=weighted, -1=exception, 2=combi, 3=weightedcombi
		type = o.lm.l[phraselist]->getTypeAt(foundcurrent->second.first);
		if (type == 0) {
			// if we already found a combi ban, we don't need to know this stuff
			if (!bannedcombi) {
				isItNaughty = true;
				bannedphrase = foundcurrent->first;
				bannedcategory = o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first, &cat);
			}
		}
		else if (type == 1) {
			// found a weighted phrase - either add one lot of its score, or one lot for every occurrence, depending on phrase filtering mode
			weight = o.lm.l[phraselist]->getWeightAt(foundcurrent->second.first) * (o.fg[filtergroup]->weighted_phrase_mode == 2 ? 1 : foundcurrent->second.second);
			weighting += weight;
			if (weight > 0) {
				currcat = o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first, &cat);
				if (cat >= 0) {
					//don't output duplicate categories
					catcurrent = listcategories.find(cat);
					if (catcurrent != listcategories.end()) {
						// add one or N times the weight to this category's score
						catcurrent->second.weight += weight * (o.fg[filtergroup]->weighted_phrase_mode == 2 ? 1 : foundcurrent->second.second);
					} else {
						listcategories[cat] = listent(weight,currcat);
					}
				}
			}

			if (o.show_weighted_found) {
				if (weightedphrase.length() > 0) {
					weightedphrase += "+";
				}
				if (weight < 0) {
					weightedphrase += "-";
				}

				weightedphrase += foundcurrent->first;
			}
#ifdef DGDEBUG
			std::cout << "found weighted phrase ("<< o.fg[filtergroup]->weighted_phrase_mode << "): "
				<< foundcurrent->first << " x" << foundcurrent->second.second << " (per phrase: "
				<< o.lm.l[phraselist]->getWeightAt(foundcurrent->second.first)
				<< ", calculated: " << weight << ")" << std::endl;
#endif
		}
		else if (type == -1) {
			isException = true;
			isItNaughty = false;
			// Exception phrase found:
			// Exception search term found:
			whatIsNaughtyLog = o.language_list.getTranslation(searchterms ? 457 : 604);
			whatIsNaughtyLog += foundcurrent->first;
			whatIsNaughty = "";
			whatIsNaughtyCategories = o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first, NULL);
			return;  // no point in going further
		}
		foundcurrent++;
	}

#ifdef DGDEBUG
	std::cout << "WEIGHTING: " << weighting << std::endl;
#endif

	// store the lowest negative weighting or highest positive weighting out of all filtering runs, preferring to store positive weightings.
	if ((weighting < 0 && naughtiness <= 0 && weighting < naughtiness) || (naughtiness >= 0 && weighting > naughtiness) || (naughtiness < 0 && weighting > 0) ) {
		naughtiness = weighting;
	}

#ifdef DGDEBUG
	std::cout << "NAUGHTINESS: " << naughtiness << std::endl;
#endif

	// *now* we can safely get down to the whole banning business!

	if (bannedcombi) {
		isItNaughty = true;
		// Banned combination phrase found:
		// Banned combination search term found:
		whatIsNaughtyLog = o.language_list.getTranslation(searchterms ? 452: 400);
		whatIsNaughtyLog += combifound;
		// Banned combination phrase found.
		// Banned combination search term found.
		whatIsNaughty = o.language_list.getTranslation(searchterms ? 453 : 401);
		whatIsNaughtyCategories = bannedcategory.toCharArray();
		return;
	}

	if (isItNaughty) {
		// Banned phrase found:
		// Banned search term found:
		whatIsNaughtyLog = o.language_list.getTranslation(searchterms ? 450 : 300);
		whatIsNaughtyLog += bannedphrase;
		// Banned phrase found.
		// Banned search term found.
		whatIsNaughty = o.language_list.getTranslation(searchterms ? 451 : 301);
		whatIsNaughtyCategories = bannedcategory.toCharArray();
		return;
	}

	if (weighting > limit) {
		isItNaughty = true;
		// Weighted phrase limit of
		// Weighted search term limit of
		whatIsNaughtyLog = o.language_list.getTranslation(searchterms ? 454 : 402);
		whatIsNaughtyLog += String(limit).toCharArray();
		whatIsNaughtyLog += " : ";
		whatIsNaughtyLog += String(weighting).toCharArray();
		if (o.show_weighted_found) {
			whatIsNaughtyLog += " (";
			whatIsNaughtyLog += weightedphrase;
			whatIsNaughtyLog += ")";
		}
		// Weighted phrase limit exceeded.
		// Weighted search term limit exceeded.
		whatIsNaughty = o.language_list.getTranslation(searchterms ? 455 : 403);
		// Generate category list, sorted with highest scoring first.
		bool nonempty = false;
		bool belowthreshold = false;
		String categories;
		std::deque<listent> sortable_listcategories;
		catcurrent = listcategories.begin();
		while (catcurrent != listcategories.end()) {
			sortable_listcategories.push_back(catcurrent->second);
			catcurrent++;
		}
		std::sort(sortable_listcategories.begin(), sortable_listcategories.end());
		std::deque<listent>::iterator k = sortable_listcategories.begin();
		while (k != sortable_listcategories.end()) {
			// if category display threshold is in use, apply it
			if (!belowthreshold && (o.fg[filtergroup]->category_threshold > 0)
				&& (k->weight < o.fg[filtergroup]->category_threshold))
			{
				whatIsNaughtyDisplayCategories = categories.toCharArray();
				belowthreshold = true;
				usedisplaycats = true;
			}
			if (k->string.length() > 0) {
				if (nonempty) categories += ", ";
				categories += k->string;
				nonempty = true;
			}
			k++;
			// if category threshold is set to show only the top category,
			// everything after the first loop is below the threshold
			if (!belowthreshold && o.fg[filtergroup]->category_threshold < 0) {
				whatIsNaughtyDisplayCategories = categories.toCharArray();
				belowthreshold = true;
				usedisplaycats = true;
			}
		}
		whatIsNaughtyCategories = categories.toCharArray();
		return;
	}
	// whatIsNaughty is what is displayed in the browser
	// whatIsNaughtyLog is what is logged in the log file if at all
}



// *
// *
// * PICS code
// *
// *



// check the document's PICS rating
// when checkPICS is called we assume checkphrase has made the document lower case.
// data must also have been NULL terminated.
void NaughtyFilter::checkPICS(const char *file, unsigned int filtergroup)
{
	(*o.fg[filtergroup]).pics1.match(file);
	if (!(*o.fg[filtergroup]).pics1.matched()) {
		return;
	}			// exit if not found
	for (int i = 0; i < (*o.fg[filtergroup]).pics1.numberOfMatches(); i++) {
		checkPICSrating((*o.fg[filtergroup]).pics1.result(i), filtergroup);  // pass on result for further
		// tests
	}
}

// the meat of the process 
void NaughtyFilter::checkPICSrating(std::string label, unsigned int filtergroup)
{
	(*o.fg[filtergroup]).pics2.match(label.c_str());
	if (!(*o.fg[filtergroup]).pics2.matched()) {
		return;
	}			// exit if not found
	String lab(label.c_str());  // convert to a String for easy manip
	String r;
	String service;
	for (int i = 0; i < (*o.fg[filtergroup]).pics2.numberOfMatches(); i++) {
		r = (*o.fg[filtergroup]).pics2.result(i).c_str();  // ditto
		r = r.after("(");
		r = r.before(")");  // remove the brackets

		// Only check the substring of lab that is between
		// the start of lab (or the end of the previous match)
		// and the start of this rating.
		// It is possible to have multiple ratings in one pics-label.
		// This is done on e.g. http://www.jesusfilm.org/
		if (i == 0) {
			service = lab.subString(0, (*o.fg[filtergroup]).pics2.offset(i));
		} else {
			service = lab.subString((*o.fg[filtergroup]).pics2.offset(i - 1) + (*o.fg[filtergroup]).pics2.length(i - 1), (*o.fg[filtergroup]).pics2.offset(i));
		}

		if (service.contains("safesurf")) {
			checkPICSratingSafeSurf(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("evaluweb")) {
			checkPICSratingevaluWEB(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("microsys")) {
			checkPICSratingCyberNOT(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("icra")) {
			checkPICSratingICRA(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("rsac")) {
			checkPICSratingRSAC(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("weburbia")) {
			checkPICSratingWeburbia(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("vancouver")) {
			checkPICSratingVancouver(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("icec")) {
			checkPICSratingICEC(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		if (service.contains("safenet")) {
			checkPICSratingSafeNet(r, filtergroup);
			if (isItNaughty) {
				return;
			}
		}
		// check label for word denoting rating system then pass on to the
		// appropriate function the rating String.
	}
}

void NaughtyFilter::checkPICSagainstoption(String s, const char *l, int opt, std::string m)
{
	if (s.indexOf(l) != -1) {
		// if the rating contains the label then:
		int i = 0;
		// get the rating label value
		s = s.after(l);
		if (s.indexOf(" ") != -1) {
			//remove anything after it
			s = s.before(" ");
		}
		// sanity checking
		if (s.length() > 0) {
			i = s.toInteger();  // convert the value in a String to an integer
			if (opt < i) {	// check its value against the option in config file
				isItNaughty = true;  // must be over limit
				whatIsNaughty = m + " ";
				whatIsNaughty += o.language_list.getTranslation(1000);
				// PICS labeling level exceeded on the above site.
				whatIsNaughtyCategories = "PICS";
				whatIsNaughtyLog = whatIsNaughty;
			}
		}
	}
}

// The next few functions are flippin' obvious so no explanation...
void NaughtyFilter::checkPICSratingevaluWEB(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "rating ", (*o.fg[filtergroup]).pics_evaluweb_rating, "evaluWEB age range");
}

void NaughtyFilter::checkPICSratingWeburbia(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "s ", (*o.fg[filtergroup]).pics_weburbia_rating, "Weburbia rating");
}

void NaughtyFilter::checkPICSratingCyberNOT(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "sex ", (*o.fg[filtergroup]).pics_cybernot_sex, "CyberNOT sex rating");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "other ", (*o.fg[filtergroup]).pics_cybernot_sex, "CyberNOT other rating");
}

// Korean PICS
void NaughtyFilter::checkPICSratingICEC(String r, unsigned int filtergroup) {
    checkPICSagainstoption(r, "y ", (*o.fg[filtergroup]).pics_icec_rating, "ICEC rating");
}

// Korean PICS
void NaughtyFilter::checkPICSratingSafeNet(String r, unsigned int filtergroup) {
	checkPICSagainstoption(r, "n ", (*o.fg[filtergroup]).pics_safenet_nudity, "SafeNet nudity");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "s ", (*o.fg[filtergroup]).pics_safenet_sex, "SafeNet sex");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "v ", (*o.fg[filtergroup]).pics_safenet_violence, "SafeNet violence");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "l ", (*o.fg[filtergroup]).pics_safenet_language, "SafeNet language");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "i ", (*o.fg[filtergroup]).pics_safenet_gambling, "SafeNet gambling");
	if (isItNaughty) {return;}
	checkPICSagainstoption(r, "h ", (*o.fg[filtergroup]).pics_safenet_alcoholtobacco, "SafeNet alcohol tobacco");
}

void NaughtyFilter::checkPICSratingRSAC(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "v ", (*o.fg[filtergroup]).pics_rsac_violence, "RSAC violence");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "s ", (*o.fg[filtergroup]).pics_rsac_sex, "RSAC sex");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "n ", (*o.fg[filtergroup]).pics_rsac_nudity, "RSAC nudity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "l ", (*o.fg[filtergroup]).pics_rsac_language, "RSAC language");
}

void NaughtyFilter::checkPICSratingVancouver(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "MC ", (*o.fg[filtergroup]).pics_vancouver_multiculturalism, "Vancouvermulticulturalism");
	checkPICSagainstoption(r, "Edu ", (*o.fg[filtergroup]).pics_vancouver_educationalcontent, "Vancouvereducationalcontent");
	checkPICSagainstoption(r, "Env ", (*o.fg[filtergroup]).pics_vancouver_environmentalawareness, "Vancouverenvironmentalawareness");
	checkPICSagainstoption(r, "Tol ", (*o.fg[filtergroup]).pics_vancouver_tolerance, "Vancouvertolerance");
	checkPICSagainstoption(r, "V ", (*o.fg[filtergroup]).pics_vancouver_violence, "Vancouverviolence");
	checkPICSagainstoption(r, "S ", (*o.fg[filtergroup]).pics_vancouver_sex, "Vancouversex");
	checkPICSagainstoption(r, "P ", (*o.fg[filtergroup]).pics_vancouver_profanity, "Vancouverprofanity");
	checkPICSagainstoption(r, "SF ", (*o.fg[filtergroup]).pics_vancouver_safety, "Vancouversafety");
	checkPICSagainstoption(r, "Can ", (*o.fg[filtergroup]).pics_vancouver_canadiancontent, "Vancouvercanadiancontent");
	checkPICSagainstoption(r, "Com ", (*o.fg[filtergroup]).pics_vancouver_commercialcontent, "Vancouvercommercialcontent");
	checkPICSagainstoption(r, "Gam ", (*o.fg[filtergroup]).pics_vancouver_gambling, "Vancouvergambling");
}

void NaughtyFilter::checkPICSratingSafeSurf(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "000 ", (*o.fg[filtergroup]).pics_safesurf_agerange, "Safesurf age range");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "001 ", (*o.fg[filtergroup]).pics_safesurf_profanity, "Safesurf profanity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "002 ", (*o.fg[filtergroup]).pics_safesurf_heterosexualthemes, "Safesurf heterosexualthemes");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "003 ", (*o.fg[filtergroup]).pics_safesurf_homosexualthemes, "Safesurf ");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "004 ", (*o.fg[filtergroup]).pics_safesurf_nudity, "Safesurf nudity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "005 ", (*o.fg[filtergroup]).pics_safesurf_violence, "Safesurf violence");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "006 ", (*o.fg[filtergroup]).pics_safesurf_sexviolenceandprofanity, "Safesurf sexviolenceandprofanity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "007 ", (*o.fg[filtergroup]).pics_safesurf_intolerance, "Safesurf intolerance");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "008 ", (*o.fg[filtergroup]).pics_safesurf_druguse, "Safesurf druguse");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "009 ", (*o.fg[filtergroup]).pics_safesurf_otheradultthemes, "Safesurf otheradultthemes");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "00A ", (*o.fg[filtergroup]).pics_safesurf_gambling, "Safesurf gambling");
	if (isItNaughty) {
		return;
	}
}

void NaughtyFilter::checkPICSratingICRA(String r, unsigned int filtergroup)
{
	checkPICSagainstoption(r, "la ", (*o.fg[filtergroup]).pics_icra_languagesexual, "ICRA languagesexual");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ca ", (*o.fg[filtergroup]).pics_icra_chat, "ICRA chat");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "cb ", (*o.fg[filtergroup]).pics_icra_moderatedchat, "ICRA moderatedchat");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "lb ", (*o.fg[filtergroup]).pics_icra_languageprofanity, "ICRA languageprofanity");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "lc ", (*o.fg[filtergroup]).pics_icra_languagemildexpletives, "ICRA languagemildexpletives");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "na ", (*o.fg[filtergroup]).pics_icra_nuditygraphic, "ICRA nuditygraphic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nb ", (*o.fg[filtergroup]).pics_icra_nuditymalegraphic, "ICRA nuditymalegraphic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nc ", (*o.fg[filtergroup]).pics_icra_nudityfemalegraphic, "ICRA nudityfemalegraphic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nd ", (*o.fg[filtergroup]).pics_icra_nuditytopless, "ICRA nuditytopless");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ne ", (*o.fg[filtergroup]).pics_icra_nuditybottoms, "ICRA nuditybottoms");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nf ", (*o.fg[filtergroup]).pics_icra_nuditysexualacts, "ICRA nuditysexualacts");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ng ", (*o.fg[filtergroup]).pics_icra_nudityobscuredsexualacts, "ICRA nudityobscuredsexualacts");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nh ", (*o.fg[filtergroup]).pics_icra_nuditysexualtouching, "ICRA nuditysexualtouching");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ni ", (*o.fg[filtergroup]).pics_icra_nuditykissing, "ICRA nuditykissing");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nr ", (*o.fg[filtergroup]).pics_icra_nudityartistic, "ICRA nudityartistic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ns ", (*o.fg[filtergroup]).pics_icra_nudityeducational, "ICRA nudityeducational");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "nt ", (*o.fg[filtergroup]).pics_icra_nuditymedical, "ICRA nuditymedical");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oa ", (*o.fg[filtergroup]).pics_icra_drugstobacco, "ICRA drugstobacco");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ob ", (*o.fg[filtergroup]).pics_icra_drugsalcohol, "ICRA drugsalcohol");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oc ", (*o.fg[filtergroup]).pics_icra_drugsuse, "ICRA drugsuse");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "od ", (*o.fg[filtergroup]).pics_icra_gambling, "ICRA gambling");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oe ", (*o.fg[filtergroup]).pics_icra_weaponuse, "ICRA weaponuse");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "of ", (*o.fg[filtergroup]).pics_icra_intolerance, "ICRA intolerance");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "og ", (*o.fg[filtergroup]).pics_icra_badexample, "ICRA badexample");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "oh ", (*o.fg[filtergroup]).pics_icra_pgmaterial, "ICRA pgmaterial");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "va ", (*o.fg[filtergroup]).pics_icra_violencerape, "ICRA violencerape");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vb ", (*o.fg[filtergroup]).pics_icra_violencetohumans, "ICRA violencetohumans");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vc ", (*o.fg[filtergroup]).pics_icra_violencetoanimals, "ICRA violencetoanimals");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vd ", (*o.fg[filtergroup]).pics_icra_violencetofantasy, "ICRA violencetofantasy");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "ve ", (*o.fg[filtergroup]).pics_icra_violencekillinghumans, "ICRA violencekillinghumans");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vf ", (*o.fg[filtergroup]).pics_icra_violencekillinganimals, "ICRA violencekillinganimals");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vg ", (*o.fg[filtergroup]).pics_icra_violencekillingfantasy, "ICRA violencekillingfantasy");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vh ", (*o.fg[filtergroup]).pics_icra_violenceinjuryhumans, "ICRA violenceinjuryhumans");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vi ", (*o.fg[filtergroup]).pics_icra_violenceinjuryanimals, "ICRA violenceinjuryanimals");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vj ", (*o.fg[filtergroup]).pics_icra_violenceinjuryfantasy, "ICRA violenceinjuryfantasy");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vr ", (*o.fg[filtergroup]).pics_icra_violenceartisitic, "ICRA violenceartisitic");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vs ", (*o.fg[filtergroup]).pics_icra_violenceeducational, "ICRA violenceeducational");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vt ", (*o.fg[filtergroup]).pics_icra_violencemedical, "ICRA violencemedical");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vu ", (*o.fg[filtergroup]).pics_icra_violencesports, "ICRA violencesports");
	if (isItNaughty) {
		return;
	}
	checkPICSagainstoption(r, "vk ", (*o.fg[filtergroup]).pics_icra_violenceobjects, "ICRA violenceobjects");

}
