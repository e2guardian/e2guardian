// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_CONNECTIONHANDLER
#define __HPP_CONNECTIONHANDLER

// INCLUDES
#include <iostream>
#include <string>
#include "OptionContainer.hpp"
#include "FOptionContainer.hpp"
#include "LOptionContainer.hpp"
#include "NaughtyFilter.hpp"
#include "Socket.hpp"
#include "HTTPHeader.hpp"
#include "ICAPHeader.hpp"
#include "FatController.hpp"
#include "Auth.hpp"
#include "AccessLogger.hpp"

// DECLARATIONS

// add a known clean URL to the cache
void addToClean(String &url, const int fg);


// the ConnectionHandler class - handles filtering, scanning, and blocking of
// data passed between a client and the external proxy.
class ConnectionHandler
{
    public:
    ConnectionHandler();
//        : clienthost(NULL) {
 //       ch_isiphost.comp(",*[a-z|A-Z].*");
  //      ldl = o.currentList();
   //     load_id = ldl->reload_id;
    //}
    ~ConnectionHandler()
    {
        delete clienthost;
    };

    int load_id;
    // pass data between proxy and client, filtering as we go.
    int handlePeer(Socket &peerconn, String &ip, unsigned int LC_type);

    auth_rec SBauth;      // record persists for whole connection

    // TODO: Extract to new class
    static bool getdnstxt(std::string &clientip, String &user);

    private:
    int filtergroup;
    int oldfg = 0;
    bool matchedip;
    bool persistent_authed;
    bool overide_persist;
    bool is_real_user = false;

    std::string clientuser;
    std::string oldclientuser;
    std::string *clienthost;
    std::string urlparams;
    std::list<AccessLogger::postinfo> postparts;
    String lastcategory;
    std::shared_ptr<LOptionContainer> ldl;

    void peerDiag(const char *message, Socket &peersock );
    void upstreamDiag(const char *message, Socket &proxysock );

    int handleConnection(Socket &peerconn, String &ip, bool ismitm, Socket &proxyconn);

    int handleTHTTPSConnection(Socket &peerconn, String &ip, Socket &proxysock);
    int handleICAPConnection(Socket &peerconn, String &ip, Socket &proxysock);
    int handleICAPreqmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead, AuthPlugin *auth_plugin) ;
    int handleICAPresmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead, DataBuffer &docbody) ;

    bool get_original_ip_port(Socket &peerconn, NaughtyFilter &checkme);

    String dns_error(int herror);

    // write a log entry containing the given data (if required)
  //  void doLog(std::string &who, std::string &from, String &where, unsigned int &port,
  //      std::string &what, String &how, off_t &size, std::string *cat, bool isnaughty, int naughtytype,
  //      bool isexception, bool istext, struct timeval *thestart, bool cachehit, int code,
  //      std::string &mimetype, bool wasinfected, bool wasscanned, int naughtiness, int filtergroup,
  //      HTTPHeader *reqheader, int message_no = 999, bool contentmodified = false,
  //      bool urlmodified = false, bool headermodified = false,
   //     bool headeradded = false);

    void doLog(std::string &who, std::string &from, NaughtyFilter &cm, std::list<AccessLogger::postinfo> *postparts);
    void doRQLog(std::string &who, std::string &from, NaughtyFilter &cm, std::string &funct);

    bool  goMITM(NaughtyFilter &checkme, Socket &proxysock, Socket &peerconn,bool &persistProxy,  bool &authed, bool &persistent_authed, String &ip, std::string &clientip, bool transparent = false);


    // perform URL encoding on a string
    std::string miniURLEncode(const char *s);

  //  RegExp ch_isiphost;
  //  RegResult Rch_isiphost;
    bool genDenyAccess(Socket &peerconn, String &eheader, String &ebody, HTTPHeader *header, HTTPHeader *docheader,
                       String *url, NaughtyFilter *checkme, std::string *clientuser, std::string *clientip,
                       int filtergroup,
                       bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow = false);

    // show the relevant banned page depending upon the report level settings, request type, etc.
    bool denyAccess(Socket *peerconn, Socket *proxysock, HTTPHeader *header, HTTPHeader *docheader,
        String *url, NaughtyFilter *checkme, std::string *clientuser, std::string *clientip,
        int filtergroup, bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow = false);

    // create temporary ban bypass URLs/cookies
    String hashedURL(String *url, int filtergroup, std::string *clientip, bool infectionbypass, std::string *user);
    // is this a temporary filter bypass URL?
    int isBypassURL(String url, const char *magic, const char *clientip, std::string btype, std::string &user);
    // is this a scan bypass URL? (download previously scanned file)
    bool isScanBypassURL(String url, const char *magic, const char *clientip);
    String hashedCookie(String *url, const char *magic, std::string *clientip, int bypasstimestamp);

    // do content scanning (AV filtering) and naughty filtering
    void contentFilter(HTTPHeader *docheader, HTTPHeader *header, DataBuffer *docbody, Socket *proxysock,
        Socket *peerconn, int *headersent, bool *pausedtoobig, off_t *docsize, NaughtyFilter *checkme,
        bool wasclean, int filtergroup, std::deque<CSPlugin *> &responsescanner, std::string *clientuser,
        std::string *clientip, bool *wasinfected, bool *wasscanned, bool isbypass, String &url, String &domain,
        bool *scanerror, bool &contentmodified, String *csmessage);

    // send a file to the client - used during bypass of blocked downloads
    off_t sendFile(Socket *peerconn, NaughtyFilter &cm, String &url, bool is_icap = false, ICAPHeader *icap_head = NULL);

    bool writeback_error( NaughtyFilter &cm, Socket & cl_sock, int mess_no1, int mess_no2, std::string mess);
    bool gen_error_mess( Socket &peerconn, NaughtyFilter &cm, String &eheader, String &ebody, int mess_no1, int mess_no2, std::string mess);

    bool doAuth(int &auth_result, bool &authed, int &filtergroup,AuthPlugin* auth_plugin, Socket & peerconn, Socket &proxysock,
                HTTPHeader & header, NaughtyFilter &cm, bool only_client_ip = false, bool isconnect_like = false);

    bool doAuth(int &auth_result, bool &authed, int &filtergroup,AuthPlugin* auth_plugin, Socket & peerconn,
                HTTPHeader & header, NaughtyFilter &cm, bool only_client_ip = false, bool isconnect_like = false);

    bool checkByPass( NaughtyFilter &checkme, std::shared_ptr<LOptionContainer> & ldl, HTTPHeader &header, Socket & proxysock,
    Socket &peerconn, std::string &clientip );
    bool sendScanFile( Socket &peerconn, NaughtyFilter &checkme, bool is_icap = false, ICAPHeader *icaphead = NULL);

    void check_search_terms(NaughtyFilter &cm);
    void check_content(NaughtyFilter &cm, DataBuffer &docbody, Socket &proxysock, Socket &peerconn,
                                          std::deque<CSPlugin *> &responsescanners);
    //ssl certificat checking
    void checkCertificate(String &hostname, Socket *sslSock, NaughtyFilter *checkme);

    int sendProxyConnect(String &hostname, Socket *sock, NaughtyFilter *checkme);

    int determineGroup(std::string &user, int &fg, StoryBoard & uglc, NaughtyFilter &checkme, int story_entry);
    int connectUpstream(Socket &sock, NaughtyFilter &cm,int port);
};

char *get_TLS_SNI(char *bytes, int* len);

#endif

