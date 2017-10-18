
// all content blocking/filtering is triggered from calls inside here
int ConnectionHandler::handleConnection(Socket &peerconn, String &ip, bool ismitm, Socket &proxysock,
                                        stat_rec* &dystat)
{
    //// Initilization start
    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.proxy_timeout);

    HTTPHeader docheader; // to hold the returned page header from proxy
    HTTPHeader header; // to hold the incoming client request headeri(ldl)

    // set a timeout as we don't want blocking 4 eva
    // this also sets how long a peerconn will wait for other requests
    header.setTimeout(o.pcon_timeout);
    docheader.setTimeout(o.exchange_timeout);

    // to hold the returned page
    DataBuffer docbody;
    docbody.setTimeout(o.proxy_timeout);

    // flags
    bool waschecked = false;
    bool wasrequested = false;
    bool isexception = false;
    bool isourwebserver = false;
    bool wasclean = false;
    bool cachehit = false;
    bool isbypass = false;
    bool iscookiebypass = false;
    bool isvirusbypass = false;
    bool isscanbypass = false;
    bool ispostblock = false;
    bool pausedtoobig = false;
    bool wasinfected = false;
    bool wasscanned = false;
    bool contentmodified = false;
    bool urlmodified = false;
    bool headermodified = false;
    bool headeradded = false;
    bool isconnect;
    bool ishead;
    bool scanerror;
    bool ismitmcandidate = false;
    bool do_mitm = false;
    bool is_ssl = false;
    int bypasstimestamp = 0;
    bool urlredirect = false;

    // 0=none,1=first line,2=all
    int headersent = 0;
    int message_no = 0;

    // Content scanning plugins to use for request (POST) & response data
    std::deque<CSPlugin *> requestscanners;
    std::deque<CSPlugin *> responsescanners;

    std::string mimetype("-");

    String url;
    String logurl;
    String urld;
    String urldomain;

    std::string exceptionreason; // to hold the reason for not blocking
    std::string exceptioncat;

    off_t docsize = 0; // to store the size of the returned document for logging

    std::string clientip(ip.toCharArray()); // hold the clients ip

    delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;

    // clear list of parameters extracted from URL
    urlparams.clear();

    // clear out info about POST data
    postparts.clear();

#ifdef DGDEBUG // debug stuff surprisingly enough
    std::cout << dbgPeerPort << " -got peer connection" << std::endl;
    std::cout << dbgPeerPort << clientip << std::endl;
#endif
    // proxysock now passed to function
    // Socket proxysock;

    try {   //// still initialisation
        int rc;

#ifdef DGDEBUG
        int pcount = 0;
#endif

        // assume all requests over the one persistent connection are from
        // the same user. means we only need to query the auth plugin until
        // we get credentials, then assume they are valid for all reqs. on
        // the persistent connection.
        std::string oldclientuser;
        std::string room;

        int oldfg = 0, gmode;
        bool authed = false;
        bool isbanneduser = false;

        FDTunnel fdt;
        NaughtyFilter checkme;
        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistOutgoing = true;
        bool persistPeer = true;
        bool persistProxy = true;
////      end of initial

        //// read in first header
        bool firsttime = true;
        if(!header.in(&peerconn, true, true)) {
           if (peerconn.getFD() > -1) {

               int err = peerconn.getErrno();
               int pport = peerconn.getPeerSourcePort();

               syslog(LOG_INFO, "%d No header recd from client - errno: %d", pport, err);
           } else {
               syslog(LOG_INFO, "Client connection closed early - no request header received");
           }
            firsttime = false;
            persistPeer = false;
        }; // get header from client, allowing persistency and breaking on reloadconfig
        ++dystat->reqs;
        //
        //// End of set-up section
        //
        //// Start of main loop
        //

        // maintain a persistent connection
        while ((firsttime || persistPeer) && !ttg)
        {
#ifdef DGDEBUG
            std::cout << " firsttime =" << firsttime << "ismitm =" << ismitm << " clientuser =" << clientuser << " group = " << filtergroup << std::endl;
#endif
           // std::shared_ptr<LOptionContainer> ldl = o.currentLists();
            ldl = o.currentLists();
            if (firsttime) {
                // reset flags & objects next time round the loop
                firsttime = false;

                // quick trick for the very first connection :-)
                if (!ismitm)
                    persistProxy = false;
            } else {   //// read in next set of request headers
// another round...
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persisting (count " << ++pcount << ")" << std::endl;
                syslog(LOG_ERR, "Served %d requests on this connection so far - ismitm=%d", pcount, ismitm);
                std::cout << dbgPeerPort << " - " << clientip << std::endl;
#endif
                header.reset();
                if(!header.in(&peerconn, true, true)) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Persistent connection closed" << std::endl;
#endif
                    break;
                }
                ++dystat->reqs;

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);

                waschecked = false; // flags
                wasrequested = false;
                isexception = false;
                isourwebserver = false;
                wasclean = false;
                cachehit = false;
                isbypass = false;
                iscookiebypass = false;
                isvirusbypass = false;
                bypasstimestamp = 0;
                isscanbypass = false;
                ispostblock = false;
                pausedtoobig = false;
                wasinfected = false;
                wasscanned = false;
                contentmodified = false;
                urlmodified = false;
                headermodified = false;
                headeradded = false;
                urlredirect = false;

                authed = false;
                isbanneduser = false;

                requestscanners.clear();
                responsescanners.clear();

                headersent = 0; // 0=none,1=first line,2=all
                //delete clienthost;
                //clienthost = NULL; // and the hostname, if available
                matchedip = false;
                urlparams.clear();
                postparts.clear();
                docsize = 0; // to store the size of the returned document for logging
                message_no = 0;
                mimetype = "-";
                exceptionreason = "";
                exceptioncat = "";
                room = "";

                // reset docheader & docbody
                // headers *should* take care of themselves on the next in()
                // actually not entirely true for docheader - we may read
                // certain properties of it (in denyAccess) before we've
                // actually performed the next in(), so make sure we do a full
                // reset now.
                docheader.reset();
                docbody.reset();

                // our filter
                checkme.reset();
            }

            url = header.getUrl(false, ismitm);
            logurl = header.getLogUrl(false, ismitm);
            urld = header.decode(url);
            urldomain = url.getHostname();
            is_ssl = header.requestType().startsWith("CONNECT");

            //If proxy connction is not persistent...
            if (!persistProxy) {     //// connect to proxy if not connected
                try {
                    // ...connect to proxy
                    proxysock.setTimeout(1000);
                    for (int i = 0; i < o.proxy_timeout_sec; i++) {
                        rc = proxysock.connect(o.proxy_ip, o.proxy_port);

                        if (!rc) {
                            if (i > 0) {
                                syslog(LOG_ERR, "Proxy responded after %d retrys", i);
                            }
                            break;
                        } else {
                            if (!proxysock.isTimedout())
                                  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                        }
                    }
                    if (rc) {
#ifdef DGDEBUG
                        std::cerr << dbgPeerPort << " -Error connecting to proxy" << std::endl;
#endif
                        syslog(LOG_ERR, "Proxy not responding after %d trys - ip client: %s destination: %s - %s", o.proxy_timeout_sec, clientip.c_str(), urldomain.c_str(), strerror(errno));
                        if (proxysock.isTimedout()) {
                            message_no = 201;
                            peerconn.writeString("HTTP/1.0 504 Gateway Time-out\nContent-Type: text/html\n\n");
                            peerconn.writeString(
                                    "<HTML><HEAD><TITLE>e2guardian - 504 Gateway Time-out</TITLE></HEAD><BODY><H1>e2guardian - 504 Gateway Time-out</H1>");
                            peerconn.writeString(o.language_list.getTranslation(201));
                            peerconn.writeString("</BODY></HTML>\n");
                        } else {
                            message_no = 202;
                            peerconn.writeString("HTTP/1.0 502 Gateway Error\nContent-Type: text/html\n\n");
                            peerconn.writeString(
                                    "<HTML><HEAD><TITLE>e2guardian - 502 Gateway Error</TITLE></HEAD><BODY><H1>e2guardian - 502 Gateway Error</H1>");
                            peerconn.writeString(o.language_list.getTranslation(202));
                            peerconn.writeString("</BODY></HTML>\n");
                        }
                        return 3;
                    }
                } catch (std::exception &e) {
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << " -exception while creating proxysock: " << e.what() << std::endl;
#endif
                }
            }

#ifdef DGDEBUG
            std::cerr << getpid() << "Start URL " << url.c_str() << "is_ssl=" << is_ssl << "ismitm=" << ismitm << std::endl;
#endif

            // checks for bad URLs to prevent security holes/domain obfuscation.
            if (header.malformedURL(url)) {
                ///try
                    // writestring throws exception on error/timeout
                    // The requested URL is malformed.
                    message_no = 200;
                    peerconn.writeString("HTTP/1.0 400 Bad Request\nContent-Type: text/html\n\n");
                    peerconn.writeString("<HTML><HEAD><TITLE>e2guardian - 400 Bad Request</TITLE></HEAD><BODY><H1>e2guardian - 400 Bad Request</H1>");
                    peerconn.writeString(o.language_list.getTranslation(200));
                    peerconn.writeString("</BODY></HTML>\n");
                proxysock.close(); // close connection to proxy
                // catch (std::exception &e)
                //
                break;
            }

            urld = header.decode(url);

            if (urldomain == "internal.test.e2guardian.org") {
                    peerconn.writeString("HTTP/1.0 200 \nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian internal test</TITLE></HEAD><BODY><H1>e2guardian internal test OK</H1> ");
                    peerconn.writeString("</BODY></HTML>\n");
                proxysock.close(); // close connection to proxy
                break;
            }

            // do total block list checking here
            if (o.use_total_block_list && o.inTotalBlockList(urld)) {
                //if ( header.requestType().startsWith("CONNECT"))
                if (is_ssl) {
                        peerconn.writeString("HTTP/1.0 404 Banned Site\nContent-Type: text/html\n\n<HTML><HEAD><TITLE>Protex - Banned Site</TITLE></HEAD><BODY><H1>Protex - Banned Site</H1> ");
                        peerconn.writeString(logurl.c_str());
                        // The requested URL is malformed.
                        peerconn.writeString("</BODY></HTML>\n");
                } else { // write blank graphic
                        peerconn.writeString("HTTP/1.0 200 OK\n");
                    o.banned_image.display(&peerconn);
                }
                proxysock.close(); // close connection to proxy
                break;
            }

            // don't let the client connection persist if the client doesn't want it to.
            persistOutgoing = header.isPersistent();
            //
            //
            //// Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
            if (!persistent_authed) {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Not got persistent credentials for this connection - querying auth plugins" << std::endl;
#endif
                bool dobreak = false;
                if (o.authplugins.size() != 0) {
                    // We have some auth plugins load
                    int authloop = 0;
                    String tmp;

                    for (std::deque<Plugin *>::iterator i = o.authplugins_begin; i != o.authplugins_end; i++) {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Querying next auth plugin..." << std::endl;
#endif
                        // try to get the username & parse the return value
                        auth_plugin = (AuthPlugin *)(*i);

                        // auth plugin selection for multi ports
                        //
                        //
                        // Logic changed to allow auth scan with multiple ports as option to auth-port
                        //       fixed mapping
                        //
                        if (o.map_auth_to_ports) {
                            if (o.filter_ports.size() > 1) {
                                tmp = o.auth_map[peerconn.getPort()];
                            } else {
                                // auth plugin selection for one port
                                tmp = o.auth_map[authloop];
                                authloop++;
                            }

                            if (tmp.compare(auth_plugin->getPluginName().toCharArray()) == 0) {
                                rc = auth_plugin->identify(peerconn, proxysock, header, clientuser, is_real_user);
                            } else {
                                rc = DGAUTH_NOMATCH;
                            }
                        } else {
                            rc = auth_plugin->identify(peerconn, proxysock, header, clientuser, is_real_user);
                        }

                        if (rc == DGAUTH_NOMATCH) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin did not find a match; querying remaining plugins" << std::endl;
#endif
                            continue;
                        } else if (rc == DGAUTH_REDIRECT) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin told us to redirect client to \"" << clientuser << "\"; not querying remaining plugins" << std::endl;
#endif
                            // ident plugin told us to redirect to a login page
                            String writestring("HTTP/1.0 302 Redirect\r\nLocation: ");
                            writestring += clientuser;
                            writestring += "\r\n\r\n";
                            peerconn.writeString(writestring.toCharArray());   // no action on failure
                            dobreak = true;
                            break;
                        } else if (rc == DGAUTH_OK_NOPERSIST) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin  returned OK but no persist not setting persist auth" << std::endl;
#endif
                            overide_persist = true;
                        } else if (rc < 0) {
                            if (!is_daemonised)
                                std::cerr << "Auth plugin returned error code: " << rc << std::endl;
                            syslog(LOG_ERR, "Auth plugin returned error code: %d", rc);
                            dobreak = true;
                            break;
                        }
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Auth plugin found username " << clientuser << " (" << oldclientuser << "), now determining group" << std::endl;
#endif
                        if (clientuser == oldclientuser) {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Same user as last time, re-using old group no." << std::endl;
#endif
                            authed = true;
                            filtergroup = oldfg;
                            break;
                        }
                        // try to get the filter group & parse the return value
                        rc = auth_plugin->determineGroup(clientuser, filtergroup);
                        if (rc == DGAUTH_OK) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin found username & group; not querying remaining plugins" << std::endl;
#endif
                            authed = true;
                            break;
                        } else if (rc == DGAUTH_NOMATCH) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin did not find a match; querying remaining plugins" << std::endl;
#endif
                            continue;
                        } else if (rc == DGAUTH_NOUSER) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin found username \"" << clientuser << "\" but no associated group; not querying remaining plugins" << std::endl;
#endif
                            filtergroup = 0; //default group - one day configurable?
                            authed = true;
                            break;
                        } else if (rc < 0) {
                            if (!is_daemonised)
                                std::cerr << "Auth plugin returned error code: " << rc << std::endl;
                            syslog(LOG_ERR, "Auth plugin returned error code: %d", rc);
                            dobreak = true;
                            break;
                        }
                    } // end of querying all plugins (for)

                    // break the peer loop
                    if (dobreak)
                        break;

                    if ((!authed) || (filtergroup < 0) || (filtergroup >= o.numfg)) {
#ifdef DGDEBUG
                        if (!authed)
                            std::cout << dbgPeerPort << " -No identity found; using defaults" << std::endl;
                        else
                            std::cout << dbgPeerPort << " -Plugin returned out-of-range filter group number; using defaults" << std::endl;
#endif
                        // If none of the auth plugins currently loaded rely on querying the proxy,
                        // such as 'ident' or 'ip', then pretend we're authed. What this flag
                        // actually controls is whether or not the query should be forwarded to the
                        // proxy (without pre-emptive blocking); we don't want this for 'ident' or
                        // 'ip', because Squid isn't necessarily going to return 'auth required'.
                        authed = !o.auth_needs_proxy_query;
#ifdef DGDEBUG
                        if (!o.auth_needs_proxy_query)
                            std::cout << dbgPeerPort << " -No loaded auth plugins require parent proxy queries; enabling pre-emptive blocking despite lack of authentication" << std::endl;
#endif
                        clientuser = "-";
                        filtergroup = 0; //default group - one day configurable?
                    } else {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Identity found; caching username & group" << std::endl;
#endif
                        if (auth_plugin->is_connection_based && !overide_persist) {
#ifdef DGDEBUG
                            std::cout << "Auth plugin is for a connection-based auth method - keeping credentials for entire connection" << std::endl;
#endif
                            persistent_authed = true;
                        }
                        oldclientuser = clientuser;
                        oldfg = filtergroup;
                    }
                } else {
// We don't have any auth plugins loaded
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -No auth plugins loaded; using defaults & feigning persistency" << std::endl;
#endif
                    authed = true;
                    clientuser = "-";
                    filtergroup = 0;
                    persistent_authed = true;
                }
            } else {
// persistent_authed == true
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Already got credentials for this connection - not querying auth plugins" << std::endl;
#endif
                authed = true;
            }

            gmode = ldl->fg[filtergroup]->group_mode;

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -username: " << clientuser << std::endl;
            std::cout << dbgPeerPort << " -filtergroup: " << filtergroup << std::endl;
            std::cout << dbgPeerPort << " -groupmode: " << gmode << std::endl;
#endif
//
//
// End of Authentication Checking
//
//

#ifdef __SSLMITM
            //			Set if candidate for MITM
            //			(Exceptions will not go MITM)
            ismitmcandidate = is_ssl && ldl->fg[filtergroup]->ssl_mitm && (header.port == 443);
#endif

            //
            //
            // Now check if user or machine is banned and room-based checking
            //
            //
            // filter group modes are: 0 = banned, 1 = filtered, 2 = exception.
            // is this user banned?
            isbanneduser = (gmode == 0);

            if (o.use_xforwardedfor) {
                bool use_xforwardedfor;
                if (o.xforwardedfor_filter_ip.size() > 0) {
                    use_xforwardedfor = false;
                    for (unsigned int i = 0; i < o.xforwardedfor_filter_ip.size(); i++) {
                        if (strcmp(clientip.c_str(), o.xforwardedfor_filter_ip[i].c_str()) == 0) {
                            use_xforwardedfor = true;
                            break;
                        }
                    }
                } else {
                    use_xforwardedfor = true;
                }
                if (use_xforwardedfor == 1) {
                    std::string xforwardip(header.getXForwardedForIP());
                    if (xforwardip.length() > 6) {
                        clientip = xforwardip;
                    }
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -using x-forwardedfor:" << clientip << std::endl;
#endif
                }
            }

            // is this machine banned?
            bool isbannedip = ldl->inBannedIPList(&clientip, clienthost);
            bool part_banned;
            if (isbannedip)
                matchedip = clienthost == NULL;
            else {
                if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &isexception, urld)) {
#ifdef DGDEBUG
                    std::cout << " isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << isexception << std::endl;
#endif
                    if (isbannedip) {
                        matchedip = clienthost == NULL;
                    }
                    if (isexception) {
                        // do reason codes etc
                        exceptionreason = o.language_list.getTranslation(630);
                        exceptionreason.append(room);
                        exceptionreason.append(o.language_list.getTranslation(631));
                        message_no = 632;
                    }
                }
            }

/*            if (o.forwarded_for) {
                header.addXForwardedFor(clientip); // add squid-like entry
            }
*/
#ifdef ENABLE_ORIG_IP
            // if working in transparent mode and grabbing of original IP addresses is
            // enabled, does the original IP address match one of those that the host
            // we are going to resolves to?
            // Resolves http://www.kb.cert.org/vuls/id/435052
            if (o.get_orig_ip) {
                // XXX This will currently only work on Linux/Netfilter.
                sockaddr_in origaddr;
                socklen_t origaddrlen(sizeof(sockaddr_in));
                // Note: we assume that for non-redirected connections, this getsockopt call will
                // return the proxy server's IP, and not -1.  Hence, comparing the result with
                // the return value of Socket::getLocalIP() should tell us that the client didn't
                // connect transparently, and we can assume they aren't vulnerable.
                if (getsockopt(peerconn.getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen) < 0) {
                    syslog(LOG_ERR, "Failed to get client's original destination IP: %s", strerror(errno));
                    break;
                }

                std::string orig_dest_ip(inet_ntoa(origaddr.sin_addr));
                if (orig_dest_ip == peerconn.getLocalIP()) {
// The destination IP before redirection is the same as the IP the
// client has actually been connected to - they aren't connecting transparently.
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -SO_ORIGINAL_DST and getLocalIP are equal; client not connected transparently" << std::endl;
#endif
                } else {
                    // Look up domain from request URL, and check orig IP against resolved IPs
                    addrinfo hints;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    addrinfo *results;
                    int result = getaddrinfo(urldomain.c_str(), NULL, &hints, &results);
                    if (result) {
                        freeaddrinfo(results);
                        syslog(LOG_ERR, "Cannot resolve hostname for host header checks: %s", gai_strerror(errno));
                        break;
                    }
                    addrinfo *current = results;
                    bool matched = false;
                    while (current != NULL) {
                        if (orig_dest_ip == inet_ntoa(((sockaddr_in *)(current->ai_addr))->sin_addr)) {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << urldomain << " matched to original destination of " << orig_dest_ip << std::endl;
#endif
                            matched = true;
                            break;
                        }
                        current = current->ai_next;
                    }
                    freeaddrinfo(results);
                    if (!matched) {
// Host header/URL said one thing, but the original destination IP said another.
// This is exactly the vulnerability we want to prevent.
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << urldomain << " DID NOT MATCH original destination of " << orig_dest_ip << std::endl;
#endif
                        syslog(LOG_ERR, "Destination host of %s did not match the original destination IP of %s", urldomain.c_str(), orig_dest_ip.c_str());
                            // writestring throws exception on error/timeout
                            peerconn.writeString("HTTP/1.0 400 Bad Request\nContent-Type: text/html\n\n");
                            peerconn.writeString("<HTML><HEAD><TITLE>e2guardian - 400 Bad Request</TITLE></HEAD><BODY><H1>e2guardian - 400 Bad Request</H1>");

                            // The requested URL is malformed.
                            peerconn.writeString(o.language_list.getTranslation(200));
                            peerconn.writeString("</BODY></HTML>\n");
                        break;
                    }
                }
            }
#endif

            //
           //// Start of virus by pass
            //

            if (header.isScanBypassURL(&logurl, ldl->fg[filtergroup]->magic.c_str(), clientip.c_str())) {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Scan Bypass URL match" << std::endl;
#endif
                isscanbypass = true;
                isbypass = true;
                exceptionreason = o.language_list.getTranslation(608);
            } else if ((ldl->fg[filtergroup]->bypass_mode != 0) || (ldl->fg[filtergroup]->infection_bypass_mode != 0)) {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -About to check for bypass..." << std::endl;
#endif
                if (ldl->fg[filtergroup]->bypass_mode != 0)
                    bypasstimestamp = header.isBypassURL(&logurl, ldl->fg[filtergroup]->magic.c_str(), clientip.c_str(), NULL);
                if ((bypasstimestamp == 0) && (ldl->fg[filtergroup]->infection_bypass_mode != 0))
                    bypasstimestamp = header.isBypassURL(&logurl, ldl->fg[filtergroup]->imagic.c_str(), clientip.c_str(), &isvirusbypass);
                if (bypasstimestamp > 0) {
#ifdef DGDEBUG
                    if (isvirusbypass)
                        std::cout << dbgPeerPort << " -Infection bypass URL match" << std::endl;
                    else
                        std::cout << dbgPeerPort << " -Filter bypass URL match" << std::endl;
#endif
                    header.chopBypass(logurl, isvirusbypass);
                    if (bypasstimestamp > 1) { // not expired
                        isbypass = true;
                        // checkme: need a TR string for virus bypass
                        exceptionreason = o.language_list.getTranslation(606);
                    }
                } else if (ldl->fg[filtergroup]->bypass_mode != 0) {
                    if (header.isBypassCookie(urldomain, ldl->fg[filtergroup]->cookie_magic.c_str(), clientip.c_str())) {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Bypass cookie match" << std::endl;
#endif
                        iscookiebypass = true;
                        isbypass = true;
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(607);
                    }
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Finished bypass checks." << std::endl;
#endif
            }

#ifdef DGDEBUG
            if (isbypass) {
                std::cout << dbgPeerPort << " -Bypass activated!" << std::endl;
            }
#endif
            //
            //// End of virus bypass
            //
            //// Start of scan by pass
            //

            if (isscanbypass) {
                //we need to decode the URL and send the temp file with the
                //correct header to the client then delete the temp file
                String tempfilename(url.after("GSBYPASS=").after("&N="));
                String tempfilemime(tempfilename.after("&M="));
                String tempfiledis(header.decode(tempfilemime.after("&D="), true));
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Original filename: " << tempfiledis << std::endl;
#endif
                String rtype(header.requestType());
                tempfilemime = tempfilemime.before("&D=");
                tempfilename = o.download_dir + "/tf" + tempfilename.before("&M=");
                try {
                    docsize = sendFile(&peerconn, tempfilename, tempfilemime, tempfiledis, url);
                    header.chopScanBypass(url);
                    url = header.getLogUrl();
                    //urld = header.decode(url);  // unneeded really

                    doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                        rtype, docsize, NULL, false, 0, isexception, false, &thestart,
                        cachehit, 200, mimetype, wasinfected, wasscanned, 0, filtergroup,
                        &header);

                    if (o.delete_downloaded_temp_files) {
                        unlink(tempfilename.toCharArray());
                    }
                } catch (std::exception &e) {
                }
                persistProxy = false;
                proxysock.close(); // close connection to proxy
                break;
            }
            //
            //// End of scan by pass
            //

            char *retchar;

            //
            //// Start of exception checking
            //
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
            if (!(isbanneduser || isbannedip || isbypass || isexception)) {
                //bool is_ssl = header.requestType() == "CONNECT";
                bool is_ip = isIPHostnameStrip(urld);
                if ((gmode == 2)) { // admin user
                    isexception = true;
                    exceptionreason = o.language_list.getTranslation(601);
                    message_no = 601;
                    // Exception client user match.
                } else if (ldl->inExceptionIPList(&clientip, clienthost)) { // admin pc
                    matchedip = clienthost == NULL;
                    isexception = true;
                    exceptionreason = o.language_list.getTranslation(600);
                    // Exception client IP match.
                }
                if (!isexception && (*ldl->fg[filtergroup]).enable_local_list) {

                    if (is_ssl && (!ismitmcandidate) && ((retchar = ldl->fg[filtergroup]->inLocalBannedSSLSiteList(urld, false, is_ip, is_ssl,lastcategory)) != NULL)) { // blocked SSL site
                        checkme.whatIsNaughty = o.language_list.getTranslation(580); // banned site
                        message_no = 580;
                        checkme.whatIsNaughty += retchar;
                        checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                        checkme.isItNaughty = true;
                        checkme.whatIsNaughtyCategories = lastcategory.toCharArray();
                    } else if (ldl->fg[filtergroup]->inLocalExceptionSiteList(urld, false, is_ip, is_ssl, lastcategory)) { // allowed site
                        if (ldl->fg[0]->isOurWebserver(url)) {
                            isourwebserver = true;
                        } else {
                            isexception = true;
                            exceptionreason = o.language_list.getTranslation(662);
                            message_no = 662;
                            // Exception site match.
                            exceptioncat = lastcategory.toCharArray();
                        }
                    } else if (ldl->fg[filtergroup]->inLocalExceptionURLList(urld, false, is_ip, is_ssl, lastcategory)) { // allowed url
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(663);
                        message_no = 663;
                        // Exception url match.
                        exceptioncat = lastcategory.toCharArray();
                    } else if ((!is_ssl) && embededRefererChecks(&header, &urld, &url, filtergroup)) { // referer exception
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(620);
                        message_no = 620;
                    }
                    // end of local lists exception checking
                }
            }

            if ((*ldl->fg[filtergroup]).enable_local_list) {
                if (authed && !(isexception || isourwebserver)) {
                    // check if this is a search request
                    if (!is_ssl)
                        checkme.isSearch = header.isSearch(ldl->fg[filtergroup]);
                    // add local grey and black checks
                    if (!ismitmcandidate || ldl->fg[filtergroup]->only_mitm_ssl_grey) {
                        requestLocalChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup, isbanneduser, isbannedip, room);
                        message_no = checkme.message_no;
                    };
                };
            }
            // original section only now called if local list not matched
            if (!(isbanneduser || isbannedip || isbypass || isexception || checkme.isGrey || checkme.isItNaughty || ldl->fg[filtergroup]->use_only_local_allow_lists)) {
                //bool is_ssl = header.requestType() == "CONNECT";
                bool is_ip = isIPHostnameStrip(urld);
                if (is_ssl && (!ismitmcandidate) && ((retchar = ldl->fg[filtergroup]->inBannedSSLSiteList(urld, false, is_ip, is_ssl, lastcategory)) != NULL)) { // blocked SSL site
                    checkme.whatIsNaughty = o.language_list.getTranslation(520); // banned site
                    message_no = 520;
                    checkme.whatIsNaughty += retchar;
                    checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                    checkme.isItNaughty = true;
                    checkme.whatIsNaughtyCategories = lastcategory.toCharArray();
                }

                if (ldl->fg[filtergroup]->inExceptionSiteList(urld, true, is_ip, is_ssl, lastcategory)) // allowed site
                {
                    if (ldl->fg[0]->isOurWebserver(url)) {
                        isourwebserver = true;
                    } else {
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(602);
                        message_no = 602;
                        // Exception site match.
                        exceptioncat = lastcategory.toCharArray();
                    }
                } else if (ldl->fg[filtergroup]->inExceptionURLList(urld, true, is_ip, is_ssl, lastcategory)) { // allowed url
                    isexception = true;
                    exceptionreason = o.language_list.getTranslation(603);
                    message_no = 603;
                    // Exception url match.
                    exceptioncat = lastcategory.toCharArray();
                } else if ((rc = ldl->fg[filtergroup]->inExceptionRegExpURLList(urld, lastcategory)) > -1) {
                    isexception = true;
                    // exception regular expression url match:
                    exceptionreason = o.language_list.getTranslation(609);
                    message_no = 609;
                    exceptionreason += ldl->fg[filtergroup]->exception_regexpurl_list_source[rc].toCharArray();
                    exceptioncat = lastcategory.toCharArray();
                } else if (!(*ldl->fg[filtergroup]).enable_local_list) {
                    if (embededRefererChecks(&header, &urld, &url, filtergroup)) { // referer exception
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(620);
                        message_no = 620;
                    }
                }
            }
            // if bannedregexwithblanketblock and exception check nevertheless
            if ((*ldl->fg[filtergroup]).enable_regex_grey && isexception && (!(isbypass || isbanneduser || isbannedip))) {
                requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup, isbanneduser, isbannedip, room);
                // Debug deny code //
                // syslog(LOG_ERR, "code: %d", checkme.message_no); //
                if (checkme.message_no == 503 || checkme.message_no == 508) {
                    isexception = false;
                    message_no = checkme.message_no;
                }
            }

//
// End of main exception checking
//

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -extracted url:" << urld << std::endl;
#endif

            // don't run willScanRequest if content scanning is disabled, or on exceptions if contentscanexceptions is off,
            // or on SSL (CONNECT) requests, or on HEAD requests, or if in AV bypass mode
            String reqtype(header.requestType());
            isconnect = reqtype[0] == 'C';
            ishead = reqtype[0] == 'H';

            // Query request and response scanners to see which is interested in scanning data for this request
            // TODO - Should probably block if willScanRequest returns error
            bool multipart = false;
            if (!isbannedip && !isbanneduser && !isconnect && !ishead
                && (ldl->fg[filtergroup]->disable_content_scan != 1)
                && !(isexception && !o.content_scan_exceptions)) {
                for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i) {
                    int csrc = ((CSPlugin *)(*i))->willScanRequest(header.getUrl(), clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(), false, false, isexception, isbypass);
                    if (csrc > 0)
                        responsescanners.push_back((CSPlugin *)(*i));
                    else if (csrc < 0)
                        syslog(LOG_ERR, "willScanRequest returned error: %d", csrc);
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Content scanners interested in response data: " << responsescanners.size() << std::endl;
#endif

                // Only query scanners regarding outgoing data if we are actually sending data in the request
                if (header.contentLength() > 0) {
                    // POST data log entry - fill in for single-part posts,
                    // and fill in overall "guess" for multi-part posts;
                    // latter will be overwritten with more detail about
                    // individual parts, if part-by-part filtering occurs.
                    String mtype(header.getContentType());
                    postparts.push_back(postinfo());
                    postparts.back().mimetype.assign(mtype);
                    postparts.back().size = header.contentLength();

                    if (mtype == "application/x-www-form-urlencoded" || (multipart = (mtype == "multipart/form-data"))) {
                        // Don't bother if it's a single part POST and is above max_content_ramcache_scan_size
                        if (!multipart && header.contentLength() > o.max_content_ramcache_scan_size) {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Not running willScanRequest for POST data: single-part POST with content length above size limit" << std::endl;
#endif
                        } else {
                            for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i) {
                                int csrc = ((CSPlugin *)(*i))->willScanRequest(header.getUrl(), clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(), true, !multipart, isexception, isbypass);
                                if (csrc > 0)
                                    requestscanners.push_back((CSPlugin *)(*i));
                                else if (csrc < 0)
                                    syslog(LOG_ERR, "willScanRequest returned error: %d", csrc);
                            }
                        }
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Content scanners interested in request data: " << requestscanners.size() << std::endl;
#endif
                    }
                }
            }

            if (((isexception || iscookiebypass || isvirusbypass)
                    // don't filter exception and local web server
                    // Cookie bypass so don't need to add cookie so just CONNECT (unless should content scan)
                    && !isbannedip // bad users pc
                    && !isbanneduser // bad user
                    && requestscanners.empty() && responsescanners.empty()) // doesn't need content scanning
                // bad people still need to be able to access the banned page
                || isourwebserver) {
                if(!proxysock.breadyForOutput(o.proxy_timeout))
                    cleanThrow("Unable to write to proxy",peerconn, proxysock);
#ifdef DGDEBUG
                std::cerr << dbgPeerPort << "  got past line 1257 rfo " << std::endl;
#endif

                if(!( header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true) // send proxy the request
                    && (docheader.in(&proxysock, persistOutgoing)) )) {
                    if (proxysock.isTimedout()) {
                        message_no = 200;
                        peerconn.writeString("HTTP/1.0 504 Gateway Time-out\nContent-Type: text/html\n\n");
                        peerconn.writeString(
                                "<HTML><HEAD><TITLE>e2guardian - 504 Gateway Time-out</TITLE></HEAD><BODY><H1>e2guardian - 504 Gateway Time-out</H1>");
                        peerconn.writeString(o.language_list.getTranslation(201));
                        peerconn.writeString("</BODY></HTML>\n");
                        break;
                    } else {
                        message_no = 200;
                        peerconn.writeString("HTTP/1.0 502 Gateway Error\nContent-Type: text/html\n\n");
                        peerconn.writeString(
                                "<HTML><HEAD><TITLE>e2guardian - 502 Gateway Error</TITLE></HEAD><BODY><H1>e2guardian - 502 Gateway Error</H1>");
                        peerconn.writeString(o.language_list.getTranslation(202));
                        peerconn.writeString("</BODY></HTML>\n");
                        break;
                //        cleanThrow("Unable to read header from proxy", peerconn, proxysock);
                    }
                }
                persistProxy = docheader.isPersistent();
                persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                if(!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL))
                      cleanThrow("Unable to send return header to client",peerconn, proxysock);
                // only open a two-way tunnel on CONNECT if the return code indicates success
                if (!(docheader.returnCode() == 200)) {
                    isconnect = false;
                }

                if (isconnect) {
                    persistProxy = false;
                    persistOutgoing = false;
                    persistPeer = false;
                }

                //try
                    fdt.reset(); // make a tunnel object
                    // tunnel from client to proxy and back
                    // two-way if SSL
                //syslog(LOG_INFO, "before tunnel 1324");
                     if(!fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true))
                         persistProxy = false;
//                         cleanThrow("Error Connect tunnel", peerconn,proxysock);
                //syslog(LOG_INFO, "after tunnel 1327");
                    docsize = fdt.throughput;
                try {
                    if (!isourwebserver) { // don't log requests to the web server
                        String rtype(header.requestType());
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, (exceptioncat.length() ? &exceptioncat : NULL), false, 0, isexception,
                            false, &thestart, cachehit, ((!isconnect && persistPeer) ? docheader.returnCode() : 200),
                            mimetype, wasinfected, wasscanned, 0, filtergroup, &header, message_no);
                    }
                } catch (std::exception &e) {
                }

                if (!persistProxy)
                    proxysock.close(); // close connection to proxy

                if (persistPeer)
                    continue;

                break;
            }
#ifdef NOOPP
            if ((o.max_ips > 0) && (!gotIPs(clientip))) {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -no client IP slots left" << std::endl;
#endif
                checkme.isItNaughty = true;
                //checkme.whatIsNaughty = "IP limit exceeded.  There is a ";
                checkme.message_no = 10;
                checkme.whatIsNaughty = o.language_list.getTranslation(10);
                checkme.whatIsNaughty += String(o.max_ips).toCharArray();
                //checkme.whatIsNaughty += " IP limit set.";
                checkme.whatIsNaughty += o.language_list.getTranslation(11);
                checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                //checkme.whatIsNaughtyCategories = "IP Limit";
                checkme.whatIsNaughtyCategories = o.language_list.getTranslation(71);
            }
#endif

            // URL regexp search and redirect
            if (!is_ssl)
                urlredirect = header.urlRedirectRegExp(ldl->fg[filtergroup]);
            if (urlredirect) {
                url = header.redirecturl();
#ifdef DGDEBUG
                std::cout << "urlRedirectRegExp told us to redirect client to \"" << url << std::endl;
#endif
                proxysock.close();
                String writestring("HTTP/1.0 302 Redirect\nLocation: ");
                writestring += url;
                writestring += "\n\n";
                peerconn.writeString(writestring.toCharArray());
                break;
            }

            if (!is_ssl)
                headeradded = header.isHeaderAdded(ldl->fg[filtergroup]);

            // URL regexp search and replace
            urlmodified = header.urlRegExp(ldl->fg[filtergroup]);
            if (urlmodified) {
                url = header.getUrl();
                urld = header.decode(url);
                urldomain = url.getHostname();

                // if the user wants, re-check the exception site, URL and regex lists after modification.
                // this allows you to, for example, force safe search on Google URLs, then flag the
                // request as an exception, to prevent questionable language in returned site summaries
                // from blocking the entire request.
                // this could be achieved with exception phrases (which are, of course, always checked
                // after the URL) too, but there are cases for both, and flexibility is good.
                if (o.recheck_replaced_urls && !(isbanneduser || isbannedip)) {
                    //bool is_ssl = header.requestType() == "CONNECT";
                    bool is_ip = isIPHostnameStrip(urld);
                    if (ldl->fg[filtergroup]->inExceptionSiteList(urld, true, is_ip, is_ssl, lastcategory)) { // allowed site
                        if (ldl->fg[0]->isOurWebserver(url)) {
                            isourwebserver = true;
                        } else {
                            isexception = true;
                            exceptionreason = o.language_list.getTranslation(602);
                            message_no = 602;
                            // Exception site match.
                            exceptioncat = lastcategory.toCharArray();
                        }
                    } else if (ldl->fg[filtergroup]->inExceptionURLList(urld, true, is_ip, is_ssl, lastcategory)) { // allowed url
                        isexception = true;
                        exceptionreason = o.language_list.getTranslation(603);
                        message_no = 603;
                        // Exception url match.
                        exceptioncat = lastcategory.toCharArray();
                    } else if ((rc = ldl->fg[filtergroup]->inExceptionRegExpURLList(urld, lastcategory)) > -1) {
                        isexception = true;
                        // exception regular expression url match:
                        exceptionreason = o.language_list.getTranslation(609);
                        message_no = 609;
                        exceptionreason += ldl->fg[filtergroup]->exception_regexpurl_list_source[rc].toCharArray();
                        exceptioncat = lastcategory.toCharArray();
                    }
                    // don't filter exception and local web server
                    if ((isexception
                            // even after regex URL replacement, we still don't want banned IPs/users viewing exception sites
                            && !isbannedip // bad users pc
                            && !isbanneduser // bad user
                            && requestscanners.empty() && responsescanners.empty())
                        || isourwebserver) {
                        if(!proxysock.breadyForOutput(o.proxy_timeout))
                            cleanThrow("Unable to write to proxy 1415",peerconn, proxysock);
#ifdef DGDEBUG
                        std::cerr << dbgPeerPort << "  got past line 1391 rfo " << std::endl;
#endif
                        if(!header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true)) // send proxy the request
                            cleanThrow("Unable to write header to proxy",peerconn, proxysock);
                        if(!docheader.in(&proxysock, persistOutgoing))
                            cleanThrow("Unable to read header from proxy",peerconn, proxysock);
                        persistProxy = docheader.isPersistent();
                        persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                        if(!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL))
                            cleanThrow("Unable to send return header to client",peerconn, proxysock);

                        // only open a two-way tunnel on CONNECT if the return code indicates success
                        if (!(docheader.returnCode() == 200)) {
                            isconnect = false;
                        }
                        if (isconnect) {
                            persistProxy = false;
                            persistOutgoing = false;
                            persistPeer = false;
                        }
                        //try 
                            fdt.reset(); // make a tunnel object
                            // tunnel from client to proxy and back
                            // two-way if SSL
                        if(!fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true) )
                            persistProxy = false;
//                            cleanThrow("Error Connect tunnel", peerconn,proxysock);
                            docsize = fdt.throughput;
                        try {
                            if (!isourwebserver) { // don't log requests to the web server
                                String rtype(header.requestType());
                                doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, (exceptioncat.length() ? &exceptioncat : NULL),
                                    false, 0, isexception, false, &thestart, cachehit, ((!isconnect && persistPeer) ? docheader.returnCode() : 200),
                                    mimetype, wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                                    // content wasn't modified, but URL was
                                    false, true, headermodified, headeradded);
                            }

                        } catch (std::exception &e) {
                        }
                        if (!persistProxy)
                            proxysock.close(); // close connection to proxy

                        if (persistPeer && proxysock.readyForOutput())
                            continue;
                        proxysock.close();
                        break;
                    }
                }
            }

            // Outgoing header modifications
            headermodified = header.headerRegExp(ldl->fg[filtergroup]);

            // if o.content_scan_exceptions is on then exceptions have to
            // pass on until later for AV scanning too.
            // Bloody annoying feature that adds mess and complexity to the code
            if (isexception) {
                checkme.isException = true;
                checkme.whatIsNaughtyLog = exceptionreason;
                checkme.whatIsNaughtyCategories = exceptioncat;
            }

            if (isconnect && !isbypass && !isexception) {
                if (!authed) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -CONNECT: user not authed - getting response to see if it's auth required" << std::endl;
#endif
                    // send header to proxy
                    if(!proxysock.breadyForOutput(o.proxy_timeout))
                        cleanThrow("Unable to send header to proxy 1439",peerconn, proxysock);


                    //proxysock.readyForOutput(o.proxy_timeout);
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << "  got past line 1465 rfo " << std::endl;
#endif
                    if(!header.out(NULL, &proxysock, __DGHEADER_SENDALL, true))
                    cleanThrow("Unable to send header to proxy 1524",peerconn, proxysock);

                    // get header from proxy
                    if(!proxysock.bcheckForInput(o.exchange_timeout))
                        cleanThrow("Unable to get header from proxy 1527",peerconn, proxysock);
                    if(!docheader.in(&proxysock, persistOutgoing))
                        cleanThrow("Unable to getr return header from proxy 1530",peerconn, proxysock);
                    persistProxy = docheader.isPersistent();
                    persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                    wasrequested = true;

                    if (docheader.returnCode() != 200) {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -CONNECT: user not authed - doing standard filtering on auth required response" << std::endl;
#endif
                        isconnect = false;
                    }
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << "isconnect=" << isconnect << " ismitmcandidate=" << ismitmcandidate << " only_mitm_ssl_grey=" << ldl->fg[filtergroup]->only_mitm_ssl_grey << std::endl;
#endif

                if (isconnect && ((!ismitmcandidate) || ldl->fg[filtergroup]->only_mitm_ssl_grey)) {
                    persistProxy = false;
                    persistPeer = false;
                    persistOutgoing = false;
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -CONNECT: user is authed/auth not required - attempting pre-emptive ban" << std::endl;
#endif
                    // if its a connect and we don't do filtering on it now then
                    // it will get tunneled and not filtered.  We can't tunnel later
                    // as its ssl so we can't see the return header etc
                    // So preemptive banning is forced on with ssl unfortunately.
                    // It is unlikely to cause many problems though.
                    requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup, isbanneduser, isbannedip, room);
                    message_no = checkme.message_no;
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -done checking" << std::endl;
#endif
                }
            }

#ifdef __SSLMITM
            //https mitm but only on port 443
            if (ldl->fg[filtergroup]->only_mitm_ssl_grey && !checkme.isSSLGrey)
                ismitmcandidate = false;
            if (!isexception && ismitmcandidate) {
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Intercepting HTTPS connection" << std::endl;
#endif

                //Do the connect request
                if (!checkme.isItNaughty && !wasrequested) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Forwarding connect request" << std::endl;
#endif
                    if(!proxysock.breadyForOutput(o.proxy_timeout))
                        cleanThrow("Unable to send header to proxy 1584",peerconn, proxysock);
                    if (isconnect)
                        header.sslsiteRegExp(ldl->fg[filtergroup]);
                    if(!header.out(NULL, &proxysock, __DGHEADER_SENDALL, true)) // send proxy the request
                        cleanThrow("Unable to send header to proxy 1586",peerconn, proxysock);
                    //check the response headers so we can go ssl
                    if(!proxysock.bcheckForInput(120000))
                        cleanThrow("Unable to get response header from proxy 1589",peerconn, proxysock);
                    if(!docheader.in(&proxysock, persistOutgoing))
                        cleanThrow("Unable to get response header from proxy 1591",peerconn, proxysock);
                    persistProxy = docheader.isPersistent();
                    persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                }

                //take care of connect fails / proxy auth requests
                if (!checkme.isItNaughty && !(docheader.returnCode() == 200)) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Connect request failed / proxy auth required. Returning data to client" << std::endl;
#endif
                    //send data to the client and let it deal with it
                    if(!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL, true))
                        cleanThrow("Unable to send response header to client 1606",peerconn, proxysock);

#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Forwarding body to client" << std::endl;
#endif
                        fdt.reset(); // make a tunnel object
                        // tunnel from proxy to client
                        if(!fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true) )
                            persistProxy = false;
//                            cleanThrow("Error forwarding body to client", peerconn,proxysock);
                        docsize = fdt.throughput;
                    try {
                        String rtype(header.requestType());
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0,
                            isexception, false, &thestart,
                            cachehit, header.returnCode(), mimetype, wasinfected,
                            wasscanned, checkme.naughtiness, filtergroup, &header, message_no, false, urlmodified, headermodified, headeradded);

                    } catch (std::exception &e) {
                    }
                        if (!persistProxy)
                            proxysock.close(); // close connection to proxy

                    if (persistPeer) {
                        continue;
                    }

                    break;
                }

                //  CA intialisation now Moved into OptionContainer so now done once on start-up
                //  instead off on every request

                X509 *cert = NULL;
                struct ca_serial caser;
                EVP_PKEY *pkey = NULL;
                bool certfromcache = false;
                //generate the cert
                if (!checkme.isItNaughty) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Getting ssl certificate for client connection" << std::endl;
#endif

                    pkey = o.ca->getServerPkey();

                    //generate the certificate but don't write it to disk (avoid someone
                    //requesting lots of places that don't exist causing the disk to fill
                    //up / run out of inodes
                    certfromcache = o.ca->getServerCertificate(urldomain.CN().c_str(), &cert,
                        &caser);
#ifdef DGDEBUG
                    if (caser.asn == NULL) {
                        std::cout << "caser.asn is NULL" << std::endl;
                    }
//				std::cout << "serials are: " << (char) *caser.asn << " " < caser.charhex  << std::endl;
#endif

                    //check that the generated cert is not null and fillin checkme if it is
                    if (cert == NULL) {
                        checkme.isItNaughty = true;
                        //checkme.whatIsNaughty = "Failed to get ssl certificate";
                        checkme.message_no = 151;
                        checkme.whatIsNaughty = o.language_list.getTranslation(151);
                        checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                        checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
                    } else if (pkey == NULL) {
                        checkme.isItNaughty = true;
                        //checkme.whatIsNaughty = "Failed to load ssl private key";
                        checkme.message_no = 153;
                        checkme.whatIsNaughty = o.language_list.getTranslation(153);
                        checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                        checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
                    }
                }

                //startsslserver on the connection to the client
                if (!checkme.isItNaughty) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Going SSL on the peer connection" << std::endl;
#endif
                    //send a 200 to the client no matter what because they managed to get a connection to us
                    //and we can use it for a blockpage if nothing else
                    std::string msg = "HTTP/1.0 200 Connection established\r\n\r\n";
                    if(!peerconn.writeString(msg.c_str()))
                        cleanThrow("Unable to send to client 1670",peerconn,proxysock);

                    if (peerconn.startSslServer(cert, pkey, o.set_cipher_list) < 0) {
                        //make sure the ssl stuff is shutdown properly so we display the old ssl blockpage
                        peerconn.stopSsl();

                        checkme.isItNaughty = true;
                        //checkme.whatIsNaughty = "Failed to negotiate ssl connection to client";
                        checkme.message_no = 154;
                        checkme.whatIsNaughty = o.language_list.getTranslation(154);
                        checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                        checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
                    }
                }

                //startsslclient connected to the proxy and check the certificate of the server
                bool badcert = false;
                if (!checkme.isItNaughty) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Going SSL on connection to proxy" << std::endl;
#endif
                    std::string certpath = std::string(o.ssl_certificate_path);
                    if (proxysock.startSslClient(certpath,urldomain)) {
                        //make sure the ssl stuff is shutdown properly so we display the old ssl blockpage
                    //    proxysock.stopSsl();

                        checkme.isItNaughty = true;
                        //checkme.whatIsNaughty = "Failed to negotiate ssl connection to server";
                        checkme.message_no = 160;
                        checkme.whatIsNaughty = o.language_list.getTranslation(160);
                        checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                        checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
                    }
		}

                if (!checkme.isItNaughty) {

#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Checking certificate" << std::endl;
#endif
                    //will fill in checkme of its own accord
                    if (ldl->fg[filtergroup]->mitm_check_cert && !ldl->fg[filtergroup]->inNoCheckCertSiteList(urldomain, false)) {
                        checkCertificate(urldomain, &proxysock, &checkme);
                        badcert = checkme.isItNaughty;
                    }
                }

                //handleConnection inside the ssl tunnel
                if (!checkme.isItNaughty) {
                    bool writecert = true;
                    if (!certfromcache) {
                        writecert = o.ca->writeCertificate(urldomain.c_str(), cert,
                            &caser);
                    }

                    //if we can't write the certificate its not the end of the world but it is slow
                    if (!writecert) {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Couldn't save certificate to on disk cache" << std::endl;
#endif
                        syslog(LOG_ERR, "Couldn't save certificate to on disk cache");
                    }
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Handling connections inside ssl tunnel" << std::endl;
#endif

                    if (authed) {
                        persistent_authed = true;
                    }

                    handleConnection(peerconn, ip, true, proxysock, dystat);
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Handling connections inside ssl tunnel: done" << std::endl;
#endif
                }
                o.ca->free_ca_serial(&caser);

                //stopssl on the proxy connection
                //if it was marked as naughty then show a deny page and close the connection
                if (checkme.isItNaughty) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -SSL Interception failed " << checkme.whatIsNaughty << std::endl;
#endif

                    String rtype(header.requestType());
                    doLog(clientuser, clientip, logurl, header.port, checkme.whatIsNaughtyLog, rtype, docsize, &checkme.whatIsNaughtyCategories, true, checkme.blocktype,
                        isexception, false, &thestart,
                        cachehit, (wasrequested ? docheader.returnCode() : 200), mimetype, wasinfected,
                        wasscanned, checkme.naughtiness, filtergroup, &header, message_no, false, urlmodified, headermodified, headeradded);

                    denyAccess(&peerconn, &proxysock, &header, &docheader, &logurl, &checkme, &clientuser,
                        &clientip, filtergroup, ispostblock, headersent, wasinfected, scanerror, badcert);
                }
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Shutting down ssl to proxy" << std::endl;
#endif
                proxysock.stopSsl();

#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Shutting down ssl to client" << std::endl;
#endif

                peerconn.stopSsl();

                //tidy up key and cert
                X509_free(cert);
                EVP_PKEY_free(pkey);

                persistProxy = false;
                proxysock.close();
                break;
            }
//if not mitm then just do the tunneling
//else
//
#endif //__SSLMITM
            // Banned rewrite SSL denied page
            if ((is_ssl == true) && (checkme.isItNaughty == true) && (ldl->fg[filtergroup]->ssl_denied_rewrite == true)) {
                header.DenySSL(ldl->fg[filtergroup]);
                String rtype(header.requestType());
                doLog(clientuser, clientip, logurl, header.port, checkme.whatIsNaughtyLog, rtype, docsize, &checkme.whatIsNaughtyCategories, true, checkme.blocktype, isexception, false, &thestart, cachehit, (wasrequested ? docheader.returnCode() : 200), mimetype, wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no, false, urlmodified, headermodified, headeradded);
                checkme.isItNaughty = false;
            }

            if (!checkme.isItNaughty && isconnect) {
                // can't filter content of CONNECT
                if (!wasrequested) {
                   if(! proxysock.breadyForOutput(o.proxy_timeout))
                    cleanThrow("Error sending header to proxy", peerconn,proxysock);
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << "  got past line 1759 rfo " << std::endl;
#endif
                    header.out(NULL, &proxysock, __DGHEADER_SENDALL, true); // send proxy the request
                } else {
                    docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);
                }
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Opening tunnel for CONNECT" << std::endl;
#endif
                    fdt.reset(); // make a tunnel object
                    // tunnel from client to proxy and back - *true* two-way tunnel
                if(!fdt.tunnel(proxysock, peerconn, true) )
                    persistProxy = false;
                    //cleanThrow("Error from 2 way tunnel", peerconn,proxysock);
                    docsize = fdt.throughput;
                try {
                    String rtype(header.requestType());
                    doLog(clientuser, clientip, logurl, header.port, exceptionreason, rtype, docsize, &checkme.whatIsNaughtyCategories, false,
                        0, isexception, false, &thestart,
                        cachehit, (wasrequested ? docheader.returnCode() : 200), mimetype, wasinfected,
                        wasscanned, checkme.naughtiness, filtergroup, &header, message_no, false, urlmodified, headermodified, headeradded);

                } catch (std::exception &e) {
                }

                if (!persistProxy)
                    proxysock.close(); // close connection to proxy

                if (persistPeer)
                    continue;

                break;
            }

            // check header sent to proxy - this is done before the send, so that pre-emptive banning
            // can be used for authenticated users. this gets around the problem of Squid fetching content
            // from sites when they're just going to get banned: not too big an issue in most cases, but
            // not good if blocking sites it would be illegal to retrieve, and allows web bugs/tracking
            // links not to be requested.
            if (authed && !isbypass && !isexception && !checkme.isItNaughty) {
                requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup,
                    isbanneduser, isbannedip, room);
                message_no = checkme.message_no;
            }

            // TODO - This post code is too big
            // Filtering of POST data
            off_t cl = header.contentLength();
            if (authed && !checkme.isItNaughty && cl > 0) {
                // Check for POST upload size blocking, unless request is an exception
                // MIME type test is just an approximation, but probably good enough

                long max_upload_size;
                max_upload_size = (*ldl->fg[filtergroup]).max_upload_size;

#ifdef DGDEBUG
                std::cout << dbgPeerPort << " max upload size general: " << max_upload_size << " filtergroup " << filtergroup << ": " << (*ldl->fg[filtergroup]).max_upload_size << std::endl;

#endif
                if (!isbypass && !isexception
                    && ((max_upload_size >= 0) && (cl > max_upload_size))
                    && multipart) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Detected POST upload violation by Content-Length header - discarding rest of POST data..." << max_upload_size << std::endl;
#endif
                    header.discard(&peerconn);
                    checkme.whatIsNaughty = (*ldl->fg[filtergroup]).max_upload_size == 0 ? o.language_list.getTranslation(700) : o.language_list.getTranslation(701);
                    // Web upload is banned.
                    checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                    checkme.whatIsNaughtyCategories = "Web upload";
                    checkme.isItNaughty = true;
                    ispostblock = true;
                } else if (!requestscanners.empty()) {
                    // POST scanning by content scanning plugins
                    if (multipart) {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Filtering multi-part POST data" << std::endl;
#endif
                        // multi-part POST, possibly including file upload
                        // retrieve each part in turn and filter it on the fly

                        // network retrieval buffer
                        char buffer[2048];
                        size_t bytes_remaining = cl;

                        // determine boundary between MIME parts
                        // limit boundary to a sensible maximum to prevent DoS
                        String boundary("--");
                        boundary.append(header.getMIMEBoundary());
                        // include trailing "\r\n" or "--" in length
                        // later on, will also include leading "\r\n"
                        // need to make sure boundary fits in half our network buffer,
                        // or we won't be able to locate instances of it reliably
                        if ((boundary.length() + 2) == 0 || (boundary.length() + 2) > 1022)
                            throw postfilter_exception("Could not determine boundary for multi-part POST");

#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Boundary: " << boundary << std::endl;
#endif

                        // Grab remaining data, including trailing boundary
                        // Split into parts and process each as we go
                        std::unique_ptr<BackedStore> part;
                        std::string rolling_buffer;
                        std::string trailer;
                        rolling_buffer.reserve(2048);
                        bool first = true;
                        bool last = false;
                        // Iterate over all parts.  Stop filtering after the first blocked part,
                        // for performance, but keep processing so that we can store all parts
                        // if necessary.
                        while (bytes_remaining > 0 && !last /*&& !checkme.isItNaughty*/) {
                            // Grab the next chunk of data
                            int bytes_this_time = bytes_remaining > (2048 - rolling_buffer.length())
                                ? (2048 - rolling_buffer.length())
                                : bytes_remaining;
                            int rc = peerconn.readFromSocketn(buffer, bytes_this_time, 0, 10000);
                            if (rc < bytes_this_time)
                                throw postfilter_exception("Could not retrieve POST data from browser");

                            // Put up to (chunk size * 2) in rolling buffer
                            rolling_buffer.append(buffer, bytes_this_time);
                            bytes_remaining -= bytes_this_time;

                            bool foundb = false;
                            do {
                                // Process data from left of buffer
                                std::string::size_type loc = rolling_buffer.find(boundary);
                                if ((loc == std::string::npos) || (rolling_buffer.length() - (loc + (boundary.length() + 2)) < 0)) {
                                    // Didn't contain the boundary, or wasn't long enough
                                    // to contain boundary plus trailer - append up to
                                    // the first half of the rolling buffer to the
                                    // current part, then discard it
                                    loc = 1024 < rolling_buffer.length() ? 1024 : rolling_buffer.length();
                                    foundb = false;
                                } else {
                                    // Contained the boundary - append data up to the
                                    // boundary, discard that data plus boundary
                                    foundb = true;
                                    // See what the two trailing bytes of the boundary are
                                    trailer.assign(rolling_buffer.substr(loc + boundary.length(), 2));
                                    if (trailer == "--")
                                        last = true;
                                    else if (trailer != "\r\n")
                                        throw postfilter_exception("Unrecognised multi-part POST boundary trailer");
                                }

                                // Store data from left-hand half of buffer
                                // Don't bother storing the preamble
                                if (!first) {
                                    if (part.get() != NULL && part->append(rolling_buffer.substr(0, loc).c_str(), loc)) {
                                        if (foundb) {
                                            // Determine where the headers end and the data begins
                                            part->finalise();
                                            const char *data = part->getData();
                                            size_t offset = 0;
                                            bool foundend = false;
                                            do {
                                                void *headend = memchr((void *)(data + offset), '\r', part->getLength() - offset);
                                                if (headend == NULL)
                                                    // not found
                                                    break;
                                                offset = (size_t)headend - (size_t)(data);
                                                if ((part->getLength() - offset) >= 4
                                                    && strncmp(data + offset, "\r\n\r\n", 4) == 0) {
                                                    // found
                                                    foundend = true;
                                                    break;
                                                }
                                                // not found, but keep looking
                                                ++offset;
                                            } while (offset < (ssize_t)(part->getLength() - 4));

                                            if (!foundend)
                                                throw postfilter_exception("End of POST data part headers not found");
#ifdef DGDEBUG
                                            std::cout << dbgPeerPort << " -POST data headers: " << std::string(data, offset) << std::endl;
#endif
                                            // Extract pertinent info from part's headers
                                            String mimetype;
                                            String disposition;
                                            size_t hdr_offset = 0;
                                            do {
                                                // Look for the end of the next header line in the section of the part
                                                // that we know consists of headers (plus the last '\r')
                                                void *headend = memchr((void *)(data + hdr_offset), '\r', (offset - hdr_offset) + 1);
                                                if (headend == NULL)
                                                    // not found
                                                    break;
                                                size_t new_hdr_offset = (size_t)headend - (size_t)(data);
                                                if ((new_hdr_offset - hdr_offset > 14)
                                                    && strncasecmp(data + hdr_offset + 9, "ype: ", 5) == 0) {
                                                    // found Content-Type
                                                    mimetype.assign(data + (hdr_offset + 14), new_hdr_offset - (hdr_offset + 14));
                                                } else if ((new_hdr_offset - hdr_offset > 21)
                                                    && strncasecmp(data + hdr_offset + 9, "isposition: ", 12) == 0) {
                                                    // found Content-Disposition
                                                    disposition.assign(data + (hdr_offset + 21), new_hdr_offset - (hdr_offset + 21));
                                                }
                                                // Restart from end of current header (also skip '\n')
                                                hdr_offset = new_hdr_offset + 2;
                                            } while (hdr_offset < offset);
#ifdef DGDEBUG
                                            std::cout << dbgPeerPort << " -POST part MIME type: " << mimetype << std::endl;
                                            std::cout << dbgPeerPort << " -POST part disposition: " << disposition << std::endl;
#endif
                                            // Put info about the part in the POST parts list, for logging
                                            if (mimetype.empty())
                                                mimetype.assign("text/plain");
                                            postparts.push_back(postinfo());
                                            postparts.back().mimetype.assign(mimetype);
                                            std::string::size_type start = disposition.find("filename=");
                                            if (start != std::string::npos) {
                                                start += 9;
                                                char endchar = ';';
                                                if (disposition[start] == '"') {
                                                    endchar = '"';
                                                    ++start;
                                                }
                                                std::string::size_type end = disposition.find(endchar, start);
                                                if (end != std::string::npos)
                                                    postparts.back().filename = disposition.substr(start, end - start);
                                                else
                                                    postparts.back().filename = disposition.substr(start);
                                            }
                                            // Don't include "\r\n\r\n" in part's body data
                                            offset += 4;
                                            postparts.back().size = part->getLength();
                                            postparts.back().bodyoffset = offset;

                                            // Pre-emptively store the data part if storage is enabled.
                                            // If, when we get to the end of the filtering, the request
                                            // is not blocked/marked for storage, all parts will then
                                            // be deleted.  We need all parts to give decent context.
                                            if (!o.blocked_content_store.empty()) {
                                                postparts.back().storedname = part->store(o.blocked_content_store.c_str());
#ifdef DGDEBUG
                                                std::cout << dbgPeerPort << " -Pre-emptively stored POST data part: " << postparts.back().storedname << std::endl;
#endif
                                            }

                                            // Run part through interested request scanning plugins
                                            if (!checkme.isItNaughty) {
                                                for (std::deque<CSPlugin *>::iterator i = requestscanners.begin(); i != requestscanners.end(); ++i) {
                                                    int csrc = (*i)->willScanData(header.getUrl(), clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(),
                                                        true, false, isexception, isbypass, disposition, mimetype, part->getLength() - offset);
#ifdef DGDEBUG
                                                    std::cerr << dbgPeerPort << " -willScanData returned: " << csrc << std::endl;
#endif
                                                    if (csrc > 0) {
                                                        csrc = (*i)->scanMemory(&header, NULL, clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(),
                                                            data + offset, part->getLength() - offset, &checkme,
                                                            &disposition, &mimetype);
                                                        if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING) {
                                                            checkme.blocktype = 1;
                                                            postparts.back().blocked = true;
                                                            // Don't delete part (yet) if in stealth mode - need to send the data upstream
                                                            if (ldl->fg[filtergroup]->reporting_level != -1)
                                                                part.reset();
                                                        }
                                                        if (csrc == DGCS_BLOCKED) {
                                                            // Send part upstream anyway if in stealth mode
                                                            if (ldl->fg[filtergroup]->reporting_level != -1)
                                                                break;
                                                        } else if (csrc == DGCS_INFECTED) {
                                                            wasinfected = true;
                                                            // Send part upstream anyway if in stealth mode
                                                            if (ldl->fg[filtergroup]->reporting_level != -1)
                                                                break;
                                                        }
                                                        //if its not clean / we errored then treat it as infected
                                                        else if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING) {
                                                            if (csrc < 0) {
                                                                syslog(LOG_ERR, "Return code from content scanner: %d", csrc);
                                                            } else {
                                                                syslog(LOG_ERR, "scanFile/Memory returned error: %d", csrc);
                                                            }
                                                            //TODO: have proper error checking/reporting here?
                                                            //at the very least, integrate with the translation system.
                                                            //checkme.whatIsNaughty = "WARNING: Could not perform content scan!";
                                                            checkme.message_no = 1203;
                                                            checkme.whatIsNaughty = o.language_list.getTranslation(1203);
                                                            checkme.whatIsNaughtyLog = (*i)->getLastMessage().toCharArray();
                                                            //checkme.whatIsNaughtyCategories = "Content scanning";
                                                            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(72);
                                                            checkme.isItNaughty = true;
                                                            checkme.isException = false;
                                                            scanerror = true;
                                                            break;
                                                        }
                                                    } else if (csrc < 0)
                                                        // TODO - Should probably block here
                                                        syslog(LOG_ERR, "willScanData returned error: %d", csrc);
                                                }
                                            }
                                            // Send whole part upstream
                                            if (!checkme.isItNaughty || ldl->fg[filtergroup]->reporting_level == -1)
                                                if(!proxysock.writeToSocket(data, part->getLength(), 0, 20000))
                                                    cleanThrow("Error sending post data to proxy", peerconn,proxysock);
                                        }
                                    } else {
                                        // Data could not be appended to the buffered POST part
                                        // - length must have exceeded maxcontentfilecachescansize,
                                        // so send the part directly upstream instead
                                        if (part.get() != NULL) {
#ifdef DGDEBUG
                                            std::cout << dbgPeerPort << " -POST data part too large, sending upstream" << std::endl;
#endif
                                            // Send what we've buffered so far, then delete the buffer
                                            part->finalise();
                                            if(!proxysock.writeToSocket(part->getData(), part->getLength(), 0, 20000))
                                                cleanThrow("Error sending post data to proxy", peerconn,proxysock);
                                            part.reset();
                                        }
                                        // Send current chunk upstream directly
                                        if(!proxysock.writeToSocket(rolling_buffer.substr(0, loc).c_str(), loc, 0, 20000))
                                           cleanThrow("Error sending post data to proxy", peerconn,proxysock);
                                    }
                                    if (foundb) {
                                        if (!checkme.isItNaughty || ldl->fg[filtergroup]->reporting_level == -1) {
                                            // Regardless of whether we were buffering or streaming, send the
                                            // boundary and trailers upstream if this was the last chunk of a part
                                            if(!proxysock.writeToSocket(boundary.c_str(), boundary.length(), 0, 10000))
                                                cleanThrow("Error sending post data to proxy", peerconn,proxysock);
                                            if(!proxysock.writeToSocket(trailer.c_str(), trailer.length(), 0, 10000))
                                                cleanThrow("Error sending post data to proxy", peerconn,proxysock);
                                            // Include final CRLF (after the trailer) after last boundary
                                            if (last)
                                                if(!proxysock.writeToSocket("\r\n", 2, 0, 10000))
                                                    cleanThrow("Error sending post data to proxy", peerconn,proxysock);
                                        }
                                        part.reset(new BackedStore(o.max_content_ramcache_scan_size, o.max_content_filecache_scan_size));
                                    }
                                }

                                // If we found the boundary, include boundary size
                                // in the length of data we will discard
                                if (foundb) {
                                    loc += boundary.length() + 2;
                                    if (first) {
// We just past the preamble/first boundary
// Send request headers and first boundary upstream
#ifdef DGDEBUG
                                        std::cout << dbgPeerPort << " -Preamble/first boundary passed; sending headers & first boundary upstream" << std::endl;
#endif
                                        if (!wasrequested && (!checkme.isItNaughty || ldl->fg[filtergroup]->reporting_level == -1)) {
                                            if(!proxysock.breadyForOutput(o.proxy_timeout))
                                            cleanThrow("Error sending headers to proxy", peerconn,proxysock);
#ifdef DGDEBUG
                                            std::cerr << dbgPeerPort << "  got past line 2098 rfo " << std::endl;
#endif
                                            // sent *without* POST data, so cannot retrieve headers yet
                                            header.out(NULL, &proxysock, __DGHEADER_SENDALL, true);
                                            wasrequested = true;
                                            if(!proxysock.writeToSocket(boundary.c_str(), boundary.length(), 0, 10000))
                                                cleanThrow("Error sending headers to proxy", peerconn,proxysock);
                                            if(!proxysock.writeToSocket(trailer.c_str(), trailer.length(), 0, 10000))
                                                cleanThrow("Error sending headers  to proxy", peerconn,proxysock);
                                        }
                                        first = false;
                                        // Clear out dummy log data so it can be filled in/
                                        // with info about each POST part individually
                                        postparts.clear();
                                        // For all boundaries after the first, include the leading CRLF
                                        boundary.insert(0, "\r\n");
                                        // Create BackedStore for first data part
                                        part.reset(new BackedStore(o.max_content_ramcache_scan_size, o.max_content_filecache_scan_size));
                                    }
                                }
                                rolling_buffer.erase(0, loc);
                            } while (foundb /*&& !checkme.isItNaughty*/);
                        } // while bytes_remaining > 0 && !last /* && not blocked */

                        // If the request is not blocked or storage has not been requested,
                        // delete all the (possibly) pre-emptively stored data parts
                        if (!o.blocked_content_store.empty() && (!checkme.isItNaughty || !checkme.store)) {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Request was not blocked/marked for storage. Deleting data parts:" << std::endl;
#endif
                            for (std::list<postinfo>::iterator i = postparts.begin(); i != postparts.end(); ++i) {
                                if (i->storedname.empty())
                                    continue;
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -Part " << i->storedname << std::endl;
#endif
                                unlink(i->storedname.c_str());
                                i->storedname.clear();
                            }
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -All parts deleted" << std::endl;
#endif
                        }

                        if (!checkme.isItNaughty) {
                            // Were we still within a part when the data came to an end?
                            // Did we not find a correctly-formatted last part boundary?
                            // Was there data (other than a CRLF) remaining after the final boundary?
                            if (rolling_buffer.length() > 2 || !last || bytes_remaining > 2) {
                                std::ostringstream ss;
                                ss << "Last part of multi-part POST was not correctly terminated.  Part length: ";
                                ss << part->getLength() << ", bytes remaining: " << bytes_remaining << ", last part found: " << last;
                                throw postfilter_exception(ss.str().c_str());
                            }
// get header from proxy
// wasrequested will have been set to true (we have had to send out
// the request headers & POST data by the time we get here), so none
// of the code below here will do this for us.
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -All parts sent upstream; retrieving response headers" << std::endl;
#endif
                            proxysock.bcheckForInput(120000);
                            docheader.in(&proxysock, persistOutgoing);
                            persistProxy = docheader.isPersistent();
                            persistPeer = persistOutgoing && docheader.wasPersistent();

#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif

                        } else {
// Was blocked - discard rest of POST data before we show the block page
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -POST data part blocked; discarding remaining POST data" << std::endl;
#endif
                            // Send rest of data upstream anyway if in stealth mode
                            if (ldl->fg[filtergroup]->reporting_level == -1) {
                                if(!proxysock.writeToSocket(rolling_buffer.c_str(), rolling_buffer.length(), 0, 10000))
                                    cleanThrow("Error sending headers  to proxy", peerconn,proxysock);
                                fdt.reset();
                                if(!fdt.tunnel(peerconn, proxysock, false, bytes_remaining, false) )
                                     cleanThrow("Error in tunneling data", peerconn,proxysock);
                                //persistProxy = false;
                                // Also retrieve response headers, if wasrequested was set to true,
                                // because nothing else will do so later on
                                if (wasrequested) {
                                    docheader.in(&proxysock, persistOutgoing);
                                    persistProxy = docheader.isPersistent();
                                    persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                                    std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                                }
                            } else
                                header.discard(&peerconn, bytes_remaining);
                        }

                    } else // if (mtype == "application/x-www-form-urlencoded")
                    {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Filtering single-part POST data" << std::endl;
#endif
                        // single-part POST (plain-text form data)
                        // we know the size for the part has already been checked by this point
                        // TODO Change this to use a BackedStore for consistency, and so that we
                        // don't have to have cut-and-pasted code in the blocked content storage
                        // implementation?  Should possibly make this a loop around a more
                        // light-weight socket read function, as even if we won't get data into the
                        // BackedStore in a zero-copy fashion, there is no reason to have *too*
                        // much copied data sat around in RAM.
                        // Also a "reserve()"-alike for BackedStore wouldn't go amiss, as we know
                        // the data size in advance.
                        char buffer[cl];
                        int rc = peerconn.readFromSocketn(buffer, cl, 0, 10000);

                        if (rc < 0)
                            throw postfilter_exception("Could not retrieve POST data from browser");

                        // Set the POST data buffer on the request, so that it
                        // does not block indefinitely trying to tunnel data that
                        // the browser has already sent
                        header.setPostData(buffer, cl);

                        // data looks like "name=value+1&name2=value+2".
                        // parse the text to remove variable names and pad with
                        // spaces at beginning & end.
                        String result(" ");
                        bool inname = true;
                        for (off_t i = 1; i < cl; ++i) {
                            if (inname) {
                                if (buffer[i] == '=')
                                    inname = false;
                            } else {
                                if (buffer[i] == '&') {
                                    inname = true;
                                    result.append(" ");
                                } else
                                    result.append(1, buffer[i]);
                            }
                        }
                        result.append(" ");

                        // turn '+' back into ' '
                        result.replaceall("+", " ");

                        // decode %xx
                        result = HTTPHeader::decode(result, true);

// Run the result through request scanners which are happy to deal with reconstituted data
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -Form data: " << result.c_str() << std::endl;
#endif
                        for (std::deque<CSPlugin *>::iterator i = requestscanners.begin(); i != requestscanners.end(); ++i) {
                            int csrc = (*i)->willScanData(header.getUrl(), clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(),
                                true, true, isexception, isbypass, "", "text/plain", result.length());
#ifdef DGDEBUG
                            std::cerr << dbgPeerPort << " -willScanData returned: " << csrc << std::endl;
#endif
                            if (csrc > 0) {
                                String mimetype("text/plain");
                                csrc = (*i)->scanMemory(&header, NULL, clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(),
                                    result.c_str(), result.length(), &checkme, NULL, &mimetype);
                                if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING) {
                                    checkme.blocktype = 1;
                                    postparts.back().blocked = true;
                                    if (checkme.store && !o.blocked_content_store.empty()) {
                                        // Write original encoded buffer to disk
                                        std::ostringstream timedprefix;
                                        timedprefix << o.blocked_content_store << '-' << time(NULL) << '-' << std::flush;
                                        std::string pfx(timedprefix.str());
                                        char storedname[pfx.length() + 7];
                                        strncpy(storedname, pfx.c_str(), pfx.length());
                                        strncpy(storedname + pfx.length(), "XXXXXX", 6);
                                        storedname[pfx.length() + 6] = '\0';
#ifdef DGDEBUG
                                        std::cout << dbgPeerPort << " -Single-part POST: storedname template: " << storedname << std::endl;
#endif
                                        int storefd;
                                        if ((storefd = mkstemp(storedname)) < 0) {
                                            std::ostringstream ss;
                                            ss << "Could not create file for single-part POST data: " << strerror(errno);
                                            throw std::runtime_error(ss.str().c_str());
                                        }
#ifdef DGDEBUG
                                        std::cout << dbgPeerPort << " -Single-part POST: storedname: " << storedname << std::endl;
#endif
                                        postparts.back().storedname = storedname;
                                        ssize_t bytes_written = 0;
                                        ssize_t rc = 0;
                                        do {
                                            rc = write(storefd, buffer + bytes_written, cl - bytes_written);
                                            if (rc > 0)
                                                bytes_written += rc;
                                        } while (bytes_written < cl && (rc > 0 || errno == EINTR));
                                        if (rc < 0 && errno != EINTR) {
                                            std::ostringstream ss;
                                            ss << "Could not write single-part POST data to file: " << strerror(errno);
                                            do {
                                                rc = close(storefd);
                                            } while (rc < 0 && errno == EINTR);
                                            throw std::runtime_error(ss.str().c_str());
                                        }
                                        do {
                                            rc = close(storefd);
                                        } while (rc < 0 && errno == EINTR);
                                    }
                                }
                                if (csrc == DGCS_BLOCKED) {
                                    break;
                                } else if (csrc == DGCS_INFECTED) {
                                    wasinfected = true;
                                    break;
                                }
                                //if its not clean / we errored then treat it as infected
                                else if (csrc != DGCS_CLEAN && csrc != DGCS_WARNING) {
                                    if (csrc < 0) {
                                        syslog(LOG_ERR, "Unknown return code from content scanner: %d", csrc);
                                    } else {
                                        syslog(LOG_ERR, "scanFile/Memory returned error: %d", csrc);
                                    }
                                    //at the very least, integrate with the translation system.
                                    //checkme.whatIsNaughty = "WARNING: Could not perform content scan!";
                                    checkme.message_no = 1203;
                                    checkme.whatIsNaughty = o.language_list.getTranslation(1203);
                                    checkme.whatIsNaughtyLog = (*i)->getLastMessage().toCharArray();
                                    checkme.whatIsNaughtyCategories = "Content scanning";
                                    checkme.whatIsNaughtyCategories = o.language_list.getTranslation(72);
                                    checkme.isItNaughty = true;
                                    checkme.isException = false;
                                    scanerror = true;
                                    break;
                                }
                            } else if (csrc < 0)
                                // TODO - Should probably block here
                                syslog(LOG_ERR, "willScanData returned error: %d", csrc);
                        }
                    }
                    // Cannot be other, unknown MIME type because MIME type
                    // is checked before CS plugins are queried (so plugin lists
                    // will be empty for other MIME types)
                }
            }
#ifdef DGDEBUG
            // Banning POST requests for unauthed users (when auth is enabled) could potentially prevent users from authenticating.
            else if (!authed)
                std::cout << dbgPeerPort << " -Skipping POST filtering because user is unauthed." << std::endl;
#endif

            if (!checkme.isItNaughty) {
                // the request is ok, so we can	now pass it to the proxy, and check the returned header
                // temp char used in various places here
                char *i;

                // send header to proxy
                if (!wasrequested) {
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << " before 2352 rfo " << std::endl;
#endif
                    if(!proxysock.breadyForOutput(o.proxy_timeout))
                        cleanThrow("Error sending headers to proxy", peerconn,proxysock);
                    //proxysock.readyForOutput(o.proxy_timeout);
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << "  got past line 2352 rfo " << std::endl;
#endif
                    header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true);
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << "  got past line 2350 proxy header out " << std::endl;
                    std::cerr << dbgPeerPort << "  exchange_timeout is " << o.exchange_timeout << std::endl;
#endif

                    // get header from proxy
                    if (proxysock.bcheckForInput(o.exchange_timeout)) {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " before docheader in 2371: "  << std::endl;
#endif
                        docheader.in(&proxysock, persistOutgoing);
                        persistProxy = docheader.isPersistent();
                        persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
                    }  else {
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -error/timeout on header in from proxy: " << persistPeer << std::endl;
                        if (proxysock.isHup())
                        std::cout << dbgPeerPort << " -proxy hung up " << std::endl;
                        if (proxysock.isTimedout())
                        std::cout << dbgPeerPort << " -proxy timedout" << std::endl;
                        if (proxysock.sockError())
                        std::cout << dbgPeerPort << " -proxy socket error" << std::endl;
#endif
                        if (proxysock.isTimedout()) {
                            message_no = 200;
                            peerconn.writeString("HTTP/1.0 504 Gateway Time-out\nContent-Type: text/html\n\n");
                            peerconn.writeString(
                                    "<HTML><HEAD><TITLE>e2guardian - 504 Gateway Time-out</TITLE></HEAD><BODY><H1>e2guardian - 504 Gateway Time-out</H1>");
                            peerconn.writeString(o.language_list.getTranslation(201));
                            peerconn.writeString("</BODY></HTML>\n");
                            break;
                        } else {
                            message_no = 200;
                            peerconn.writeString("HTTP/1.0 502 Gateway Error\nContent-Type: text/html\n\n");
                            peerconn.writeString(
                                    "<HTML><HEAD><TITLE>e2guardian - 502 Gateway Error</TITLE></HEAD><BODY><H1>e2guardian - 502 Gateway Error</H1>");
                            peerconn.writeString(o.language_list.getTranslation(202));
                            peerconn.writeString("</BODY></HTML>\n");
                            break;
                            //        cleanThrow("Unable to read header from proxy", peerconn, proxysock);
                        }
                    }

                    wasrequested = true; // so we know where we are later
                }

#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -got header from proxy" << std::endl;
                if (!persistProxy)
                    std::cout << dbgPeerPort << " -header says close, so not persisting" << std::endl;
#endif

                // if we're not careful, we can end up accidentally setting the bypass cookie twice.
                // because of the code flow, this second cookie ends up with timestamp 0, and is always disallowed.
                if (isbypass && !isvirusbypass && !iscookiebypass) {
#ifdef DGDEBUG
                    std::cout << "Setting GBYPASS cookie; bypasstimestamp = " << bypasstimestamp << std::endl;
#endif
                    String ud(urldomain);
                    if (ud.startsWith("www.")) {
                        ud = ud.after("www.");
                    }

                    if(!docheader.header.empty()) {
                        docheader.setCookie("GBYPASS", ud.toCharArray(),
                                            hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(), &clientip,
                                                         bypasstimestamp).toCharArray());

                        // redirect user to URL with GBYPASS parameter no longer appended
                        docheader.header[0] = "HTTP/1.0 302 Redirect";
                        String loc("Location: ");
                        loc += header.getUrl(true);
                        docheader.header.push_back(loc);
                        docheader.setContentLength(0);

                        persistOutgoing = false;
                        docheader.out(NULL, &peerconn, __DGHEADER_SENDALL);
                    }

                    if (!persistProxy)
                        proxysock.close(); // close connection to proxy

                    break;
                }

                // don't even bother scan testing if the content-length header indicates the file is larger than the maximum size we'll scan
                // - based on patch supplied by cahya (littlecahya@yahoo.de)
                // be careful: contentLength is signed, and max_content_filecache_scan_size is unsigned
                off_t cl = docheader.contentLength();
                if (!responsescanners.empty()) {
                    if (cl == 0)
                        responsescanners.clear();
                    else if ((cl > 0) && (cl > o.max_content_filecache_scan_size))
                        responsescanners.clear();
                }

                // now that we have the proxy's header too, we can make a better informed decision on whether or not to scan.
                // this used to be done before we'd grabbed the proxy's header, rendering exceptionvirusmimetypelist useless,
                // and exceptionvirusextensionlist less effective, because we didn't have a Content-Disposition header.
                if (!responsescanners.empty()) {
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << " -Number of response CS plugins in candidate list: " << responsescanners.size() << std::endl;
#endif
//send header to plugin here needed
//also send user and group
#ifdef DGDEBUG
                    int j = 0;
#endif
                    std::deque<CSPlugin *> newplugins;
                    for (std::deque<CSPlugin *>::iterator i = responsescanners.begin(); i != responsescanners.end(); ++i) {
                        int csrc = (*i)->willScanData(header.getUrl(), clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(),
                            false, false, isexception, isbypass, docheader.disposition(), docheader.getContentType(), docheader.contentLength());
#ifdef DGDEBUG
                        std::cerr << dbgPeerPort << " -willScanData for plugin " << j << " returned: " << csrc << std::endl;
#endif
                        if (csrc > 0)
                            newplugins.push_back(*i);
                        else if (csrc < 0)
                            // TODO Should probably block on error
                            syslog(LOG_ERR, "willScanData returned error: %d", csrc);
#ifdef DGDEBUG
                        j++;
#endif
                    }

                    // Store only those plugins which responded positively to willScanData
                    responsescanners.swap(newplugins);
                }

                // no need to check bypass mode, exception mode, auth required headers, redirections, or banned ip/user (the latter get caught by requestChecks later)
                if (!isexception && !isbypass && !(isbannedip || isbanneduser) && !docheader.isRedirection() && !docheader.authRequired()) {
                    bool download_exception = false;

                    // Check the exception file site and MIME type lists.
                    mimetype = docheader.getContentType().toCharArray();
                    if (ldl->fg[filtergroup]->inExceptionFileSiteList(urld))
                        download_exception = true;
                    else {
                        if (o.lm.l[ldl->fg[filtergroup]->exception_mimetype_list]->findInList(mimetype.c_str(), lastcategory))
                            download_exception = true;
                    }

                    // Perform banned MIME type matching
                    if (!download_exception) {
                        // If downloads are blanket blocked, block outright.
                        if (ldl->fg[filtergroup]->block_downloads) {
                            // did not match the exception list
                            checkme.whatIsNaughty = o.language_list.getTranslation(750);
                            // Blanket file download is active
                            checkme.whatIsNaughty += mimetype;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Blanket download block";
                        } else if ((i = o.lm.l[ldl->fg[filtergroup]->banned_mimetype_list]->findInList(mimetype.c_str(), lastcategory)) != NULL) {
                            // matched the banned list
                            checkme.whatIsNaughty = o.language_list.getTranslation(800);
                            // Banned MIME Type:
                            checkme.whatIsNaughty += i;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Banned MIME Type";
                        }

#ifdef DGDEBUG
                        std::cout << dbgPeerPort << mimetype.length() << std::endl;
                        std::cout << dbgPeerPort << " -:" << mimetype;
                        std::cout << dbgPeerPort << " -:" << std::endl;
#endif
                    }

                    // Perform extension matching - if not already matched the exception MIME or site lists
                    if (!download_exception) {
                        // Can't ban file extensions of URLs that just redirect
                        String tempurl(urld);
                        String tempdispos(docheader.disposition());
                        unsigned int elist, blist;
                        elist = ldl->fg[filtergroup]->exception_extension_list;
                        blist = ldl->fg[filtergroup]->banned_extension_list;
                        char *e = NULL;
                        char *b = NULL;
                        if (tempdispos.length() > 1) {
// dispos filename must take presidense
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Disposition filename:" << tempdispos << ":" << std::endl;
#endif
                            // The function expects a url so we have to
                            // generate a pseudo one.
                            tempdispos = "http://foo.bar/" + tempdispos;
                            e = ldl->fg[filtergroup]->inExtensionList(elist, tempdispos);
                            // Only need to check banned list if not blanket blocking
                            if ((e == NULL) && !(ldl->fg[filtergroup]->block_downloads))
                                b = ldl->fg[filtergroup]->inExtensionList(blist, tempdispos);
                        } else {
                            if (!tempurl.contains("?")) {
                                e = ldl->fg[filtergroup]->inExtensionList(elist, tempurl);
                                if ((e == NULL) && !(ldl->fg[filtergroup]->block_downloads))
                                    b = ldl->fg[filtergroup]->inExtensionList(blist, tempurl);
                            } else if (String(mimetype.c_str()).contains("application/")) {
                                while (tempurl.endsWith("?")) {
                                    tempurl.chop();
                                }
                                while (tempurl.contains("/")) { // no slash no url
                                    e = ldl->fg[filtergroup]->inExtensionList(elist, tempurl);
                                    if (e != NULL)
                                        break;
                                    if (!(ldl->fg[filtergroup]->block_downloads))
                                        b = ldl->fg[filtergroup]->inExtensionList(blist, tempurl);
                                    while (tempurl.contains("/") && !tempurl.endsWith("?")) {
                                        tempurl.chop();
                                    }
                                    tempurl.chop(); // get rid of the ?
                                }
                            }
                        }

                        // If downloads are blanket blocked, block unless matched the exception list.
                        // If downloads are not blanket blocked, block if matched the banned list and not the exception list.
                        if (ldl->fg[filtergroup]->block_downloads && (e == NULL)) {
                            // did not match the exception list
                            checkme.whatIsNaughty = o.language_list.getTranslation(751);
                            // Blanket file download is active
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Blanket download block";
                        } else if (!(ldl->fg[filtergroup]->block_downloads) && (e == NULL) && (b != NULL)) {
                            // matched the banned list
                            checkme.whatIsNaughty = o.language_list.getTranslation(900);
                            // Banned extension:
                            checkme.whatIsNaughty += b;
                            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                            checkme.isItNaughty = true;
                            checkme.whatIsNaughtyCategories = "Banned extension";
                        } else if (e != NULL) {
                            // intention is to match either/or of the MIME & extension lists
                            // so if it gets this far, un-naughty it (may have been naughtied by the MIME type list)
                            checkme.isItNaughty = false;
                        }
                    }
                }

                // check header sent to proxy - this could be done before the send, but we
                // want to wait until after the MIME type & extension checks, because they may
                // act as a quicker rejection. also so as not to pre-emptively ban currently
                // un-authed users.
                if (!authed && !isbypass && !isexception && !checkme.isItNaughty && !docheader.authRequired()) {
                    requestChecks(&header, &checkme, &urld, &url, &clientip, &clientuser, filtergroup,
                        isbanneduser, isbannedip, room);
                }

                // check body from proxy
                // can't do content filtering on HEAD or redirections (no content)
                // actually, redirections CAN have content
                if (!checkme.isItNaughty && (cl != 0) && !ishead) {
                    if (((docheader.isContentType("text",ldl->fg[filtergroup]) || docheader.isContentType("-",ldl->fg[filtergroup])) && !isexception) || !responsescanners.empty()) {
                        // don't search the cache if scan_clean_cache disabled & runav true (won't have been cached)
                        // also don't search cache for auth required headers (same reason)

                        // checkme: does not searching the cache if scan_clean_cache is disabled break the fancy DM's bypass stuff?
                        // probably, since it uses a "magic" status code in the cache; easier than coding yet another hash type.

                        if (o.url_cache_number > 0 && (o.scan_clean_cache || responsescanners.empty()) && !docheader.authRequired()) {
                            if (wasClean(header, urld, filtergroup)) {
                                wasclean = true;
                                cachehit = true;
                                responsescanners.clear();
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -url was clean skipping content and AV checking" << std::endl;
#endif
                            }
                        }
                        // despite the debug note above, we do still go through contentFilter for cached non-exception HTML,
                        // as content replacement rules need to be applied.
                        waschecked = true;
                        if (!responsescanners.empty()) {
#ifdef DGDEBUG
                            std::cout << dbgPeerPort << " -Filtering with expectation of a possible csmessage" << std::endl;
#endif
                            String csmessage;
                            contentFilter(&docheader, &header, &docbody, &proxysock, &peerconn, &headersent, &pausedtoobig,
                                &docsize, &checkme, wasclean, filtergroup, responsescanners, &clientuser, &clientip,
                                &wasinfected, &wasscanned, isbypass, urld, urldomain, &scanerror, contentmodified, &csmessage);
                            if (csmessage.length() > 0) {
#ifdef DGDEBUG
                                std::cout << dbgPeerPort << " -csmessage found: " << csmessage << std::endl;
#endif
                                exceptionreason = csmessage.toCharArray();
                            }
                        } else {
                            contentFilter(&docheader, &header, &docbody, &proxysock, &peerconn, &headersent, &pausedtoobig,
                                &docsize, &checkme, wasclean, filtergroup, responsescanners, &clientuser, &clientip,
                                &wasinfected, &wasscanned, isbypass, urld, urldomain, &scanerror, contentmodified, NULL);
                        }
                    }
                }
            }

            if (!isexception && checkme.isException) {
                isexception = true;
                exceptionreason = checkme.whatIsNaughtyLog;
            }

            if (o.url_cache_number > 0) {
                // add to cache if: wasn't already there, wasn't naughty, wasn't allowed by bypass/soft block, was text,
                // was virus scanned and scan_clean_cache is enabled, was a GET request,
                // and response was not a set of auth required headers (we haven't checked
                // the actual content, just the proxy's auth error page!).
                // also don't add "not modified" responses to the cache - if someone adds
                // an entry and does a soft restart, we don't want the site to end up in
                // the clean cache because someone who's already been to it hits refresh.
                if (!wasclean && !checkme.isItNaughty && !isbypass
                    && (docheader.isContentType("text",ldl->fg[filtergroup]) || (wasscanned && o.scan_clean_cache))
                    && (header.requestType() == "GET") && (docheader.returnCode() == 200)
                    && urld.length() < 2000) {
                    addToClean(urld, filtergroup);
                }
            }

            // then we deny. previously, this che/ipcsockcked the isbypass flag too; now, since bypass requests only undergo the same checking
            // as exceptions, it needn't. and in fact it mustn't, if bypass requests are to be virus scanned/blocked in the same manner as exceptions.
            // make sure we keep track of whether or not logging has been performed, as we may be in stealth mode and don't want to double log.
            bool logged = false;
            if (checkme.isItNaughty) {
                String rtype(header.requestType());
#ifdef DGDEBUG
                std::cout << "Category: " << checkme.whatIsNaughtyCategories << std::endl;
#endif
                logged = true;
                doLog(clientuser, clientip, logurl, header.port, checkme.whatIsNaughtyLog,
                    rtype, docsize, &checkme.whatIsNaughtyCategories, true, checkme.blocktype, false, false, &thestart,
                    cachehit, 403, mimetype, wasinfected, wasscanned, checkme.naughtiness, filtergroup,
                    &header, message_no, contentmodified, urlmodified, headermodified, headeradded);
                if (denyAccess(&peerconn, &proxysock, &header, &docheader, &logurl, &checkme, &clientuser, &clientip, filtergroup, ispostblock, headersent, wasinfected, scanerror)) {
                    return 0; // not stealth mode
                }

                // if get here in stealth mode
            }

            if (!wasrequested) {
                if(!proxysock.breadyForOutput(o.proxy_timeout))
                    cleanThrow("Error sending headers to proxy", peerconn,proxysock);
                //proxysock.readyForOutput(o.proxy_timeout); // exceptions on error/timeout
#ifdef DGDEBUG
                std::cerr << dbgPeerPort << "  got past line 2659 rfo " << std::endl;
#endif
                header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true); // exceptions on error/timeout
                proxysock.bcheckForInput(o.exchange_timeout); // exceptions on error/timeout
                docheader.in(&proxysock, persistOutgoing); // get reply header from proxy
                persistProxy = docheader.isPersistent();
                persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
            }

//TODO: need to change connection: close if there is plugin involved.
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -sending header to client" << std::endl;
#endif
            if(!peerconn.breadyForOutput(o.proxy_timeout))
                cleanThrow("Error sending headers to client", peerconn,proxysock);
            //peerconn.readyForOutput(o.proxy_timeout); // exceptions on error/timeout
#ifdef DGDEBUG
            std::cerr << dbgPeerPort << "  got past line 2677 rfo " << std::endl;
#endif
            if (headersent == 1) {
                docheader.out(NULL, &peerconn, __DGHEADER_SENDREST); // send rest of header to client
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -sent rest header to client" << std::endl;
#endif
            } else if (headersent == 0) {
               if(!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL)) { // send header to client
#ifdef DGDEBUG
                   std::cout << dbgPeerPort << " -sent all header to client" << std::endl;
                   std::cout << dbgPeerPort << " -waschecked:" << waschecked << std::endl;
                      } else {
                   std::cout << dbgPeerPort << " -sent all header failed to client" << std::endl;
#endif
               }
            }

            if (waschecked) {
                if (!docheader.authRequired() && !pausedtoobig) {
                    String rtype(header.requestType());
                    if (!logged) {
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                            rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0, isexception,
                            docheader.isContentType("text",ldl->fg[filtergroup]), &thestart, cachehit, docheader.returnCode(), mimetype,
                            wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                            contentmodified, urlmodified, headermodified, headeradded);
                    }
                }

                if(!peerconn.breadyForOutput(o.proxy_timeout))
                    cleanThrow("Error sending headers to client 2784", peerconn,proxysock);
                //peerconn.readyForOutput(o.proxy_timeout); // check for error/timeout needed
                //if (peerconn.isNoOpp())  break;
#ifdef DGDEBUG
                std::cerr << dbgPeerPort << "  got past line 2705 rfo " << std::endl;
#endif

                // it must be clean if we got here
                if (docbody.dontsendbody && docbody.tempfilefd > -1) {
                    // must have been a 'fancy'
                    // download manager so we need to send a special link which
                    // will get recognised and cause DG to send the temp file to
                    // the browser.  The link will be the original URL with some
                    // magic appended to it like the bypass system.

                    // format is:
                    // GSBYPASS=hash(ip+url+tempfilename+mime+disposition+secret)
                    // &N=tempfilename&M=mimetype&D=dispos

                    String ip(clientip);
                    String tempfilename(docbody.tempfilepath.after("/tf"));
                    String tempfilemime(docheader.getContentType());
                    String tempfiledis(miniURLEncode(docheader.disposition().toCharArray()).c_str());
                    String secret(ldl->fg[filtergroup]->magic.c_str());
                    String magic(ip + url + tempfilename + tempfilemime + tempfiledis + secret);
                    String hashed(magic.md5());
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -sending magic link to client: " << ip << " " << url << " " << tempfilename << " " << tempfilemime << " " << tempfiledis << " " << secret << " " << hashed << std::endl;
#endif
                    String sendurl(url);
                    if (!sendurl.after("://").contains("/")) {
                        sendurl += "/";
                    }
                    if (sendurl.contains("?")) {
                        sendurl = sendurl + "&GSBYPASS=" + hashed + "&N=";
                    } else {
                        sendurl = sendurl + "?GSBYPASS=" + hashed + "&N=";
                    }
                    sendurl += tempfilename + "&M=" + tempfilemime + "&D=" + tempfiledis;
                    docbody.dm_plugin->sendLink(peerconn, sendurl, url);

                    // can't persist after this - DM plugins don't generally send a Content-Length.
                    //TODO: need to change connection: close if there is plugin involved.
                    persistOutgoing = false;
                } else {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -sending body to client" << std::endl;
#endif
       //             syslog(LOG_INFO, " -sending body to client %d", dbgPeerPort);
                    try {docbody.out(&peerconn);} // send doc body to client
                         catch (std::exception &e) {
                             //syslog(LOG_INFO, " -problem sending body to client %d", dbgPeerPort);
                             pausedtoobig = false;
                         }
                }
//                if (pausedtoobig)
                    //syslog(LOG_INFO, " -sent PARTIAL body to client %d", dbgPeerPort);
                // else
                    //syslog(LOG_INFO, " -sent body to client d", dbgPeerPort);
                //
#ifdef DGDEBUG
                if (pausedtoobig) {
                    std::cout << dbgPeerPort << " -sent PARTIAL body to client" << std::endl;
                } else {
                    std::cout << dbgPeerPort << " -sent body to client" << std::endl;
                }
#endif
                if (pausedtoobig && !docbody.dontsendbody) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -about to start tunnel to send the rest" << std::endl;
#endif
                    fdt.reset();
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -1tunnel activated" << std::endl;
#endif
                    if(!fdt.tunnel(proxysock, peerconn, false, docheader.contentLength() - docsize, true) )
                        persistProxy = false;
                        //  cleanThrow("Error in tunnel 1", peerconn,proxysock);
                    docsize += fdt.throughput;
                    String rtype(header.requestType());
                    if (!logged) {
                        doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                            rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0, isexception,
                            docheader.isContentType("text",ldl->fg[filtergroup]), &thestart, cachehit, docheader.returnCode(), mimetype,
                            wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                            contentmodified, urlmodified, headermodified, headeradded);
                    }
                }
            } else if (!ishead) {
                // was not supposed to be checked
                fdt.reset();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -2tunnel activated" << std::endl;
#endif
                if(!fdt.tunnel(proxysock, peerconn, isconnect, docheader.contentLength(), true))
                    persistProxy = false;
                   // cleanThrow("Error in tunnel 1", peerconn,proxysock);
                docsize = fdt.throughput;
                String rtype(header.requestType());
                if (!logged) {
                    doLog(clientuser, clientip, logurl, header.port, exceptionreason,
                        rtype, docsize, &checkme.whatIsNaughtyCategories, false, 0, isexception,
                        docheader.isContentType("text",ldl->fg[filtergroup]), &thestart, cachehit, docheader.returnCode(), mimetype,
                        wasinfected, wasscanned, checkme.naughtiness, filtergroup, &header, message_no,
                        contentmodified, urlmodified, headermodified, headeradded);
                }
            }

            if (!persistProxy)
                proxysock.close();

        } // while persistOutgoing
    } catch (postfilter_exception &e) {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught a POST filtering exception: " << e.what() << std::endl;
#endif
        syslog(LOG_ERR, "POST filtering exception: %s", e.what());

        // close connection to proxy
        proxysock.close();

        return 0;
    } catch (std::exception &e) {
#ifdef DGDEBUG
        std::cerr << dbgPeerPort << " -connection handler caught an exception: " << e.what() << std::endl;
#endif
        syslog(LOG_ERR, " -connection handler caught an exception %s in thread %d", e.what(), std::this_thread::get_id() );

        // close connection to proxy
        proxysock.close();

        return -1;   // to allow calling function to re-create connection handler and hopefully clear any mem errors
    }

    if (!ismitm)
        try {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Attempting graceful connection close" << std::endl;
#endif
            //syslog(LOG_INFO, " -Attempting graceful connection close" );
            int fd = peerconn.getFD();
            if (fd > -1) {
                if (shutdown(fd, SHUT_WR) == 0) {
                    char buff[2];
                    peerconn.readFromSocket(buff, 2, 0, 5000);
                };
            };

            // close connection to the client
            peerconn.close();
            proxysock.close();
        } catch (std::exception &e) {
#ifdef DGDEBUG
            std::cerr << dbgPeerPort << " -connection handler caught an exception on connection closedown: " << e.what() << std::endl;
#endif
            // close connection to the client
            peerconn.close();
            proxysock.close();
        }

    return 0;
}
