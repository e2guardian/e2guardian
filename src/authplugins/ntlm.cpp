// NTLM auth plugin

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../Auth.hpp"
#include "../FDTunnel.hpp"
#include "../OptionContainer.hpp"
#include "../Logger.hpp"

#include <string.h>
#include <stddef.h>
#include <iconv.h>

// DEFINES

extern OptionContainer o;

// NTLM username grabbing needs to be independent of endianness

#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#define bswap16(x) bswap_16(x)
#define bswap32(x) bswap_32(x)
#else
#ifndef bswap16
#define bswap16(x) (((((u_int16_t)x) >> 8) & 0xff) | ((((u_int16_t)x) & 0xff) << 8))
#endif
#ifndef bswap32
#define bswap32(x) (((((u_int32_t)x) & 0xff000000) >> 24) | ((((u_int32_t)x) & 0x00ff0000) >> 8) | ((((u_int32_t)x) & 0x0000ff00) << 8) | ((((u_int32_t)x) & 0x000000ff) << 24))
#endif
#endif

#ifdef WORDS_BIGENDIAN
#define SSWAP(x) (bswap16((x)))
#define WSWAP(x) (bswap32((x)))
#else
#define SSWAP(x) (x)
#define WSWAP(x) (x)
#endif

// DECLARATIONS

// class name is relevant!
class ntlminstance : public AuthPlugin
{
    public:
    ntlminstance(ConfigVar &definition)
        : AuthPlugin(definition), no_auth_list(-1)
    {
        // keep credentials for all requests on a given persistent connection;
        // NTLM proxy auth is designed to be used in this manner and won't re-send credentials.
        is_connection_based = true;
        needs_proxy_query = true;
        needs_proxy_access_in_plugin = true;
        client_ip_based = false;
        // whether or not to enable the magic "transparent NTLM" (NTLM auth for transparent proxies) mode
        if (definition["transparent"] == "on") {
            logger_debug("Transparent NTLM Enabled");
            transparent = true;
            transparent_ip = definition["transparent_ip"].toCharArray();
            transparent_port = definition["transparent_port"].toInteger();
            // get short form of smoothie's hostname.
            // will be used when redirecting browsers to our NTLM
            // "webserver", as IE will interpret it as being
            // an "intranet site", and hence authenticate with it
            // automatically.
            gethostname(hostname, 256);
            char *i;
            if ((i = strstr(hostname, ".")) != NULL)
                *i = '\0';
        } else
            transparent = false;
    };

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec);

    int init(void *args);
    int quit();
    bool isTransparent();

    private:
    bool transparent;
    std::string transparent_ip;
    int transparent_port;
    char hostname[256];
    int no_auth_list;
};

// things need to be on byte boundaries here
#pragma pack(1)
struct strhdr {
    int16_t len;
    int16_t maxlen;
    int32_t offset;
};

struct ntlmhdr {
    char signature[8]; // literally NTLMSSP\0
    int32_t type; // 1, 2 or 3, auth resposes are type 3.
};

// this struct is only valid if h.type == 3
// as we only evesdrop to get userid dont care about type 1 and 2 messages
struct ntlm_auth {
    ntlmhdr h;
    strhdr lmresponse; // LANMAN challenge response
    strhdr ntresponse; // NT challenge response
    strhdr domain; // Domain to authenticate against
    strhdr user; // Username (only thing we care about atm.)
    strhdr workstation; // Workstation name
    strhdr sessionkey; // Session key for server's use
    int32_t flags; // Request flags
    char payload[256 * 6]; // String data - enough for everything at 255 chars
    // but packet does not need to be that big
};

// union so load data into buffer and the byte aligned struct gets
// filled in.
union ntlm_authenticate {
    ntlm_auth a;
    char buf[sizeof(ntlm_auth)];
};
#pragma pack()

// "template adaptor" for iconv - basically, let G++ do the hard work of
// figuring out whether or not the second parameter is const for us ;)
template <typename T>
inline size_t local_iconv_adaptor(size_t (*iconv_func)(iconv_t, T, size_t *, char **, size_t *),
    iconv_t cd, char **inbuf, size_t *inbytesleft,
    char **outbuf, size_t *outbytesleft)
{
    return iconv_func(cd, (T)inbuf, inbytesleft, outbuf, outbytesleft);
}

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *ntlmcreate(ConfigVar &definition)
{
    return new ntlminstance(definition);
}

// end of Class factory

// ntlm auth header username extraction - also lets connection persist long enough to complete NTLM negotiation
int ntlminstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec)
{
    FDTunnel fdt;
    Socket *upstreamcon;
    Socket ntlmcon;
    String url;
    if (transparent) {
        // we are actually sending to a second Squid, which just does NTLM
        ntlmcon.connect(transparent_ip, transparent_port);
        upstreamcon = &ntlmcon;
        url = h.getUrl();
        h.makeTransparent(false);
    } else {
        upstreamcon = &proxycon;
    }
    String at(h.getAuthType());

// First dance with NTLM - initial auth negociation -
    if (transparent && (at != "NTLM")) {
        // obey forwarded-for options in what we send out
        logger_debug("NTLM - forging initial auth required from origin server");

        if (!h.header[h.header.size() - 1].find("X-Forwarded-For") == 0){
            if (o.forwarded_for) {
                std::string clientip;
                clientip = peercon.getPeerIP();
                h.addXForwardedFor(clientip); // add squid-like entry
            }
        }

        // send a variant on the original request (has to be something Squid will route to the outside
        // world, and that it will require NTLM authentication for)
        String domain(url.after("?sgtransntlmdest=").after("://"));
        if (domain.contains("/"))
            domain = domain.before("/");
        domain = "http://" + domain + "/";
        h.setURL(domain);
        h.out(&peercon, upstreamcon, __E2HEADER_SENDALL);
        // grab the auth required response and make it look like it's from the origin server
        h.in(upstreamcon, true);
        h.makeTransparent(true);
        h.makePersistent();
        // send it to the client
        h.out(NULL, &peercon, __E2HEADER_SENDALL);
        if (h.contentLength() != -1)
            fdt.tunnel(*upstreamcon, peercon, false, h.contentLength(), true);
        if (h.isPersistent()) {
            // now grab the client's response to the auth request, and carry on as usual.
            h.in(&peercon, true);
            h.makeTransparent(false);
            at = h.getAuthType();
        } else {
            return E2AUTH_NOMATCH;
        }
    } else if (transparent && url.contains("?sgtransntlmdest=")) {
        // send a variant on the original request (has to be something Squid will route to the outside
        // world, and that it will require NTLM authentication for)
        String domain(url.after("?sgtransntlmdest=").after("://"));
        if (domain.contains("/"))
            domain = domain.before("/");
        domain = "http://" + domain + "/";
        h.setURL(domain);
    }

#ifdef E2DEBUG
    logger_debug("NTLM - header - ");
    for (unsigned int i = 0; i < h.header.size(); i++)
    	logger_debug(h.header[i]);
#endif

    if (at != "NTLM") {
        // if no auth currently underway, then...
        if (at.length() == 0) {
            // allow the initial request through so the client will get the proxy's initial auth required response.
            // advertise persistent connections so that parent proxy will agree to advertise NTLM support.
            logger_debug("No auth negotiation currently in progress - making initial request persistent so that proxy will advertise NTLM");
            h.makePersistent();
        }
        return E2AUTH_NOMATCH;
    }

    HTTPHeader res_hd(__HEADER_RESPONSE);

    logger_debug("NTLM - sending step 1");
    if (!h.isPersistent()) {
    	h.makePersistent();
    }
    h.out(&peercon, upstreamcon, __E2HEADER_SENDALL);

    logger_debug("NTLM - receiving step 2");
    res_hd.in(upstreamcon, true);
    if (res_hd.authRequired()) {
        logger_debug("NTLM - sending step 2");
        if (transparent)
            h.makeTransparent(true);
        res_hd.out(NULL, &peercon, __E2HEADER_SENDALL);
        if (res_hd.contentLength() != -1){
            fdt.tunnel(*upstreamcon, peercon, false, res_hd.contentLength(), true);
        }

        logger_debug("NTLM - receiving step 3");
        // Buggy with IE and Chrome: todo needs more investigations !
        h.in(&peercon, true);
        if (h.header.size() == 0) {
            return E2AUTH_NOIDENTPART;
        }
        if (transparent) {
            h.makeTransparent(false);
            String domain(url.after("?sgtransntlmdest=").after("://"));
            if (domain.contains("/"))
                domain = domain.before("/");
            domain = "http://" + domain + "/";
            h.setURL(domain);
        }

        logger_debug("NTLM - decoding type 3 message");
        std::string message(h.getAuthData());
        ntlm_authenticate auth;
        ntlm_auth *a = &(auth.a);
        static char username[256]; // fixed size
        static char username2[256];
        char *inptr = username;
        char *outptr = username2;
        size_t l, b;
        // copy the NTLM message into the union's buffer, simultaneously filling in the struct
        // Need a review IE and Chrome have many requests with INVALID message
        if ((message.length() > sizeof(ntlm_auth)) || (message.length() < offsetof(ntlm_auth, payload))) {
            std::string clientip;
            clientip = peercon.getPeerIP();
#ifdef E2DEBUG
            logger_debug("NTLM - Invalid message of length ", message.length(), ", message was: ", message, "IP: ", clientip, " header size ", h.header.size() );
            for (unsigned int i = 0; i < h.header.size(); i++)
                logger_debug(h.header[i]);
#endif
              return -3;
        }
        memcpy((void *)auth.buf, (const void *)message.c_str(), message.length());

        // verify that the message is indeed a type 3
        if (strcmp("NTLMSSP", a->h.signature) == 0 && WSWAP(a->h.type) == 3) {
            // grab the length & offset of the username within the message
            // cope with the possibility we are a different byte order to Windows
            l = SSWAP(a->user.len);
            b = WSWAP(a->user.offset);

            if ((l > 0) && (b >= 0) && (b + l) <= sizeof(a->payload) && (l <= 254)) {
                // everything is in range
                // note offsets are from start of packet - not the start of the payload area
                memcpy((void *)username, (const void *)&(auth.buf[b]), l);
                username[l] = '\0';
                // check flags - we may need to convert from UTF-16 to something more sensible
                int f = WSWAP(a->flags);
                if (f & WSWAP(0x0001)) {
                    iconv_t ic = iconv_open("UTF-8", "UTF-16LE");
                    if (ic == (iconv_t)-1) {
                        logger_error("NTLM - Cannot initialise conversion from UTF-16LE to UTF-8: ", strerror(errno));
                        iconv_close(ic);
                        return -2;
                    }
                    size_t l2 = 256;
                    local_iconv_adaptor(iconv, ic, &inptr, &l, &outptr, &l2);
                    iconv_close(ic);
                    username2[256 - l2] = '\0';
                    logger_debug("NTLM - got username (converted from UTF-16LE) ", username2);
                    string = username2;
                } else {
                    logger_debug("NTLM - got username ", username);
                    string = username;
                }
		    authrec.user_name = string;
		    authrec.user_source = "ntlm";
		    is_real_user = true;
// Ugly but needed with NTLM ...
                if (!transparent){
                    if (!h.header[h.header.size() - 1].find("X-Forwarded-For") == 0){
                        if (o.forwarded_for) {
                            std::string clientip;
                            clientip = peercon.getPeerIP();
                            h.addXForwardedFor(clientip); // add squid-like entry
                        }
                    }
                    return E2AUTH_OK;
                }
                // if in transparent mode, send a redirect to the client's original requested URL,
                // having sent the final headers to the NTLM-only Squid to do with what it will
                h.out(&peercon, upstreamcon, __E2HEADER_SENDALL);
                // also, the return code matters in ways it hasn't mattered before:
                // mustn't send a redirect if it is still 407, or we get a redirection loop
                res_hd.in(upstreamcon, true);
                if (res_hd.returnCode() == 407) {
                    res_hd.makeTransparent(false);
                    res_hd.out(NULL, &peercon, __E2HEADER_SENDALL);
                    return -10;
                }
                url = url.after("=");
                string = url.toCharArray();
                return E2AUTH_REDIRECT;
            }
        }
        return E2AUTH_NOMATCH;
    } else {
#ifdef E2DEBUG
        logger_debug("NTLM - step 2 was not part of an auth handshake!");
        for (unsigned int i = 0; i < h.header.size(); i++)
            logger_debug(h.header[i]);
#endif
        logger_error("NTLM - step 2 was not part of an auth handshake! (", h.header[0], ")");
        return -1;
    }
}

int ntlminstance::init(void *args)
{
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_NTLM_PROXY;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
	read_def_fg();
        return 0;
    } else {
        logger_error("No story_function defined in ntlm proxy auth plugin config");
        return -1;
    }
}


int ntlminstance::quit()
{
    return 0;
}

bool ntlminstance::isTransparent()
{
    return transparent;
}
