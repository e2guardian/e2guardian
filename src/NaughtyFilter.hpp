// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_NAUGHTYFILTER
#define __HPP_NAUGHTYFILTER


// INCLUDES

// DECLARATIONS

class NaughtyFilter
{
public:
	// should the content be blocked?
	bool isItNaughty;
	// should the content bypass any further filtering?
	bool isException;
	// should the browser use the categories string or the displaycategories string?
	// (related to category list thresholding)
	bool usedisplaycats;
	// blocked data type - 0 = response body, 1 = request body (POST data),
	// 2 = URL parameters (search terms)
	int blocktype;
	// flag for use by ContentScanners to say whether data should be stored
	// for future inspection.  storage only implemented for POST data.
	bool store;

	// the reason for banning, what to say about it in the logs, and the
	// categories under which banning has taken place
	std::string whatIsNaughty;
	std::string whatIsNaughtyLog;
	std::string whatIsNaughtyCategories;
	std::string whatIsNaughtyDisplayCategories;

	NaughtyFilter();
	void reset();
	void checkme(const char *rawbody, off_t rawbodylen, const String *url, const String *domain,
		unsigned int filtergroup, unsigned int phraselist, int limit, bool searchterms = false);
	
	// highest positive (or lowest negative) weighting out of
	// both phrase filtering passes (smart/raw)
	int naughtiness;

private:
	// check the banned, weighted & exception lists
	// pass in both URL & domain to activate embedded URL checking
	// (this is made optional in this manner because it's pointless
	// trying to look for links etc. in "smart" filtering mode, i.e.
	// after HTML has been removed, and in search terms.)
	void checkphrase(char *file, off_t filelen, const String *url, const String *domain,
		unsigned int filtergroup, unsigned int phraselist, int limit, bool searchterms);
	
	// check PICS ratings
	void checkPICS(const char *file, unsigned int filtergroup);
	void checkPICSrating(std::string label, unsigned int filtergroup);
	void checkPICSratingSafeSurf(String r, unsigned int filtergroup);
	void checkPICSratingevaluWEB(String r, unsigned int filtergroup);
	void checkPICSratingCyberNOT(String r, unsigned int filtergroup);
	void checkPICSratingRSAC(String r, unsigned int filtergroup);
	void checkPICSratingICRA(String r, unsigned int filtergroup);
	void checkPICSratingWeburbia(String r, unsigned int filtergroup);
	void checkPICSratingVancouver(String r, unsigned int filtergroup);

	// new Korean stuff
	void checkPICSratingICEC(String r, unsigned int filtergroup);
	void checkPICSratingSafeNet(String r, unsigned int filtergroup);

	void checkPICSagainstoption(String s, const char *l, int opt, std::string m);
};

#endif
