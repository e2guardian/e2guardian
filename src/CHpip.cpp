int ConnectionHandler::handleConnection(Socket &peerconn, String &ip, bool ismitm, Socket &proxysock,
stat_rec* &dystat) {
    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    //peerconn.setTimeout(o.proxy_timeout);
    peerconn.setTimeout(o.pcon_timeout);

    // ldl = o.currentLists();

    HTTPHeader docheader(__HEADER_RESPONSE); // to hold the returned page header from proxy
    HTTPHeader header(__HEADER_REQUEST); // to hold the incoming client request headeri(ldl)

    // set a timeout as we don't want blocking 4 eva
    // this also sets how long a peerconn will wait for other requests
    header.setTimeout(o.pcon_timeout);
    docheader.setTimeout(o.exchange_timeout);


    int bypasstimestamp = 0;

    // Content scanning plugins to use for request (POST) & response data
    std::deque<CSPlugin *> requestscanners;
    std::deque<CSPlugin *> responsescanners;

    std::string clientip(ip.toCharArray()); // hold the clients ip
    docheader.setClientIP(ip);

    if (clienthost) delete clienthost;

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

    try {
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

        int oldfg = 0;
        bool authed = false;
        bool isbanneduser = false;

        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistOutgoing = true;
        bool persistPeer = true;
        bool persistProxy = true;

        bool firsttime = true;
        if (!header.in(&peerconn, true )) {     // get header from client, allowing persistency
            if (o.logconerror) {
                if (peerconn.getFD() > -1) {

                    int err = peerconn.getErrno();
                    int pport = peerconn.getPeerSourcePort();
                    std::string peerIP = peerconn.getPeerIP();

                    syslog(LOG_INFO, "%d No header recd from client at %s - errno: %d", pport, peerIP.c_str(), err);
#ifdef DGDEBUG
                    std::cout << "pport" << " No header recd from client - errno: " << err << std::endl;
#endif
                } else {
                    syslog(LOG_INFO, "Client connection closed early - no request header received");
                }
            }
            firsttime = false;
            persistPeer = false;
        } else {
            ++dystat->reqs;
// TODO  addXFor... into HTTPHeader::in or checkheader()
            if (o.forwarded_for && !ismitm) {
                header.addXForwardedFor(clientip); // add squid-like entry
            }
#ifdef DGDEBUG
            //header.dbshowheader(&checkme.logurl, clientip.c_str());
#endif
        }
        //
        // End of set-up section
        //
        // Start of main loop
        //

        // maintain a persistent connection
        while ((firsttime || persistPeer) && !ttg)
            //    while ((firsttime || persistPeer) && !reloadconfig)
        {
#ifdef DGDEBUG
            std::cout << " firsttime =" << firsttime << "ismitm =" << ismitm << " clientuser =" << clientuser << " group = " << filtergroup << std::endl;
#endif
            ldl = o.currentLists();
            NaughtyFilter checkme(header, docheader);
            DataBuffer docbody;
            docbody.setTimeout(o.exchange_timeout);
            FDTunnel fdt;

            if (firsttime) {
                // reset flags & objects next time round the loop
                firsttime = false;

                // quick trick for the very first connection :-)
                if (!ismitm)
                    persistProxy = false;
            } else {
// another round...
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persisting (count " << ++pcount << ")" << std::endl;
                syslog(LOG_ERR, "Served %d requests on this connection so far - ismitm=%d", pcount, ismitm);
                std::cout << dbgPeerPort << " - " << clientip << std::endl;
#endif
                header.reset();
                if (!header.in(&peerconn, true )) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Persistent connection closed" << std::endl;
#endif
                    break;
                }
                ++dystat->reqs;
                // REMOVE this
                if (o.forwarded_for && !ismitm) {
                    header.addXForwardedFor(clientip); // add squid-like entry
                }
#ifdef DGDEBUG
                header.dbshowheader(&checkme.logurl, clientip.c_str());
#endif
                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

                bypasstimestamp = 0;

                authed = false;
                isbanneduser = false;

                requestscanners.clear();
                responsescanners.clear();

                matchedip = false;
                urlparams.clear();
                postparts.clear();
                checkme.mimetype = "-";
                //exceptionreason = "";
                //exceptioncat = "";
                room = "";    // CHECK THIS - surely room is persistant?????

                // reset docheader & docbody
                // headers *should* take care of themselves on the next in()
                // actually not entirely true for docheader - we may read
                // certain properties of it (in denyAccess) before we've
                // actually performed the next in(), so make sure we do a full
                // reset now.
                docheader.reset();
                docbody.reset();

            }
//
            // do all of this normalisation etc just the once at the start.
            checkme.url = header.getUrl(false, ismitm);
            checkme.baseurl = checkme.url;
            checkme.baseurl.removeWhiteSpace();
            checkme.baseurl.toLower();
            checkme.baseurl.removePTP();
            checkme.logurl = header.getLogUrl(false, ismitm);
            checkme.urld = header.decode(checkme.url);
            checkme.urldomain = checkme.url.getHostname();
            checkme.urldomain.toLower();
            checkme.isiphost = isIPHostnameStrip(checkme.urldomain);
            checkme.is_ssl = header.requestType().startsWith("CONNECT");
            checkme.isconnect = checkme.is_ssl;
            checkme.ismitm = ismitm;

            //If proxy connction is not persistent...
            if (!persistProxy) {
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
                        syslog(LOG_ERR, "Proxy not responding after %d trys - ip client: %s destination: %s - %d::%s",
                               o.proxy_timeout_sec, clientip.c_str(), checkme.urldomain.c_str(), proxysock.getErrno(),
                               strerror(proxysock.getErrno()));
                        if (proxysock.isTimedout()) {
                            writeback_error(checkme, peerconn, 201, 204, "504 Gateway Time-out");
                        } else {
                            writeback_error(checkme, peerconn, 202, 204, "502 Gateway Error");
                        }
                        peerconn.close();
                        return 3;
                    }
                } catch (std::exception &e) {
#ifdef DGDEBUG
                    std::cerr << dbgPeerPort << " -exception while creating proxysock: " << e.what() << std::endl;
#endif
                }
            }

#ifdef DGDEBUG
            std::cerr << getpid() << "Start URL " << checkme.url.c_str() << "is_ssl=" << checkme.is_ssl << "ismitm=" << ismitm << std::endl;
#endif

            // checks for bad URLs to prevent security holes/domain obfuscation.
            if (header.malformedURL(checkme.url)) {
                // The requested URL is malformed.
                writeback_error(checkme, peerconn, 200, 0, "400 Bad Request");
                proxysock.close(); // close connection to proxy
                break;
            }

            if (checkme.urldomain == "internal.test.e2guardian.org") {
                peerconn.writeString(
                        "HTTP/1.0 200 \nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian internal test</TITLE></HEAD><BODY><H1>e2guardian internal test OK</H1> ");
                peerconn.writeString("</BODY></HTML>\n");
                proxysock.close(); // close connection to proxy
                break;
            }

            // do total block list checking here
            if (o.use_total_block_list && o.inTotalBlockList(checkme.urld)) {
                if (checkme.isconnect) {
                    writeback_error(checkme, peerconn, 0, 0, "404 Banned Site");
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
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
            if (!persistent_authed) {
                if (!doAuth(authed, filtergroup, auth_plugin,  peerconn, proxysock,  header) )
                    break;
            } else {
// persistent_authed == true
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -Already got credentials for this connection - not querying auth plugins" << std::endl;
#endif
                authed = true;
            }

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -username: " << clientuser << std::endl;
            std::cout << dbgPeerPort << " -filtergroup: " << filtergroup << std::endl;
#endif
//
//
// End of Authentication Checking
//
//

#ifdef __SSLMITM
            //			Set if candidate for MITM
            //			(Exceptions will not go MITM)
            checkme.ismitmcandidate = checkme.isconnect && ldl->fg[filtergroup]->ssl_mitm && (header.port == 443);
#endif

            //
            //
            // Now check if user or machine is banned and room-based checking
            //
            //
            // is this user banned?
            isbanneduser = false;
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
                if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
                                checkme.urld)) {
#ifdef DGDEBUG
                    std::cout << " isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << checkme.isexception << std::endl;
#endif
                    if (isbannedip) {
                        matchedip = clienthost == NULL;
                    }
                    if (checkme.isexception) {
                        // do reason codes etc
                        checkme.exceptionreason = o.language_list.getTranslation(630);
                        checkme.exceptionreason.append(room);
                        checkme.exceptionreason.append(o.language_list.getTranslation(631));
                        checkme.message_no = 632;
                    }
                }
            }


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
                    int result = getaddrinfo(checkme.urldomain.c_str(), NULL, &hints, &results);
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
                            std::cout << dbgPeerPort << checkme.urldomain << " matched to original destination of " << orig_dest_ip << std::endl;
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
                        std::cout << dbgPeerPort << checkme.urldomain << " DID NOT MATCH original destination of " << orig_dest_ip << std::endl;
#endif
                        syslog(LOG_ERR, "Destination host of %s did not match the original destination IP of %s", checkme.urldomain.c_str(), orig_dest_ip.c_str());
                            writeback_error(checkme,peercon,200,0,"400 Bad Request");
                        break;
                    }
                }
            }
#endif

            //
            // Start of by pass
            //
            if (checkByPass( checkme,  ldl, header,  proxysock, peerconn, clientip, persistProxy)) {
                break;
            }

            //
            // End of scan by pass
            //

            char *retchar;

            //
            // Start of exception checking
            //
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
            if (!(isbanneduser || isbannedip || checkme.isbypass || checkme.isexception)) {
                //bool is_ssl = header.requestType() == "CONNECT";
                ///
                /// bool is_ip = isIPHostnameStrip(checkme.urld);
                // Exception client user match.
                if (ldl->inExceptionIPList(&clientip, clienthost)) { // admin pc
                    matchedip = clienthost == NULL;
                    checkme.isexception = true;
                    checkme.exceptionreason = o.language_list.getTranslation(600);
                    // Exception client IP match.
                } else {

// Main checking is now done in Storyboard function(s)
                    String funct = "checkrequest";
                    ldl->fg[filtergroup]->StoryB.runFunct(funct, checkme);
                    std::cerr << "After StoryB checkrequest " << checkme.isexception << " mess_no "
                              << checkme.message_no << std::endl;
                }
            }

            //TODO check for redirect
            // URL regexp search and edirect
            if (checkme.urlredirect) {
                checkme.url = header.redirecturl();
                proxysock.close();
                String writestring("HTTP/1.0 302 Redirect\nLocation: ");
                writestring += checkme.url;
                writestring += "\n\n";
                peerconn.writeString(writestring.toCharArray());
                break;
            }

            // TODO V5 call POST scanning code New NaughtyFilter function????

            // don't run willScanRequest if content scanning is disabled, or on exceptions if contentscanexceptions is off,
            // or on SSL (CONNECT) requests, or on HEAD requests, or if in AV bypass mode

            //TODO now send upstream and get response
            if (!checkme.isItNaughty) {
                if (!proxysock.breadyForOutput(o.proxy_timeout))
                    cleanThrow("Unable to write to proxy", peerconn, proxysock);
#ifdef DGDEBUG
                std::cerr << dbgPeerPort << "  got past line 727 rfo " << std::endl;
#endif

                if (!(header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true ) // send proxy the request
                      && (docheader.in(&proxysock, persistOutgoing)))) {
                    if (proxysock.isTimedout()) {
                        writeback_error(checkme, peerconn, 203, 204, "504 Gateway Time-out");
                    } else {
                        writeback_error(checkme, peerconn, 205, 206, "502 Gateway Error");
                    }
                    break;
                }
                persistProxy = docheader.isPersistent();
                persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
                docheader.dbshowheader(&checkme.logurl, clientip.c_str());
#endif
            }


            //TODO check response code -DONE
            if (!checkme.isItNaughty) {
                int rcode = docheader.returnCode();
                if (checkme.isconnect &&
                    (rcode != 200))  // some sort of problem or needs proxy auth - pass back to client
                {
                    checkme.ismitmcandidate = false;  // only applies to connect
                    checkme.tunnel_rest = true;
                    checkme.tunnel_2way = false;
                } else if (rcode == 407) {   // proxy auth required
                    // tunnel thru - no content
                    checkme.tunnel_rest = true;
                }
                //TODO check for other codes which do not have content payload make these tunnel_rest.
                if (checkme.isexception)
                    checkme.tunnel_rest = true;
            }

            //TODO if ismitm - GO MITM (new function??)
            // check ssl_grey - or cover in storyboard???
            if (checkme.isconnect && !checkme.isexception && checkme.ismitmcandidate) {
                std::cerr << "Going MITM ...." << std::endl;
                goMITM(checkme, proxysock, peerconn, persistProxy, authed, persistent_authed, ip, dystat, clientip);
                if (!checkme.isItNaughty)
                    break;
                persistPeer = false;
                persistProxy = false;
            }

            //TODO call SB checkresponse

            //TODO send response header to client
            if (!checkme.isItNaughty) {
                if (!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL, false ))
                    cleanThrow("Unable to send return header to client", peerconn, proxysock);
            }
            checkme.tunnel_rest = true;

            //TODO if not grey tunnel response
            if (!checkme.isItNaughty && checkme.tunnel_rest) {
                if (!fdt.tunnel(proxysock, peerconn, false, docheader.contentLength(), true))
                    persistProxy = false;
                checkme.docsize = fdt.throughput;
//                         cleanThrow("Error Connect tunnel", peerconn,proxysock);
                //syslog(LOG_INFO, "after tunnel 1327");

            }

            //TODO - if grey content check

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Forwarding body to client" << std::endl;
#endif
            //TODO Log
            if (!checkme.isourwebserver) { // don't log requests to the web server
                doLog(clientuser, clientip, checkme);
            }


            if (!persistProxy)
                proxysock.close(); // close connection to proxy

            if (persistPeer) {
                continue;
            }

            break;
        }
        } catch (std::exception & e)
        {
#ifdef DGDEBUG
        std::cout << dbgPeerPort << " -connection handler caught an exception: " << e.what() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        if(o.logconerror)
            syslog(LOG_ERR, " -connection handler caught an exception %s" , e.what());

        // close connection to proxy
        proxysock.close();
            return -1;
        }
    if (!ismitm)
        try {
#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Attempting graceful connection close" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
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
            std::cout << dbgPeerPort << " -connection handler caught an exception on connection closedown: " << e.what() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            // close connection to the client
            peerconn.close();
            proxysock.close();
        }

    return 0;
