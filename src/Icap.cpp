#include "ConnectionHandler.hpp"
#include "StoryBoard.hpp"

int ConnectionHandler::handleICAPConnection(Socket &peerconn, String &ip, Socket &proxysock, stat_rec* &dystat) {
    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.pcon_timeout);


    // set a timeout as we don't want blocking 4 eva
    // this also sets how long a peerconn will wait for other requests
    //header.setTimeout(o.pcon_timeout);
    //docheader.setTimeout(o.exchange_timeout);

    std::string clientip(ip.toCharArray()); // hold the ICAP clients ip

    if (clienthost) delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;


#ifdef DGDEBUG // debug stuff surprisingly enough
    std::cerr << dbgPeerPort << " -got ICAP peer connection" << std::endl;
    std::cerr << dbgPeerPort << clientip << std::endl;
#endif

    try {
        int rc;


        int oldfg = 0;
        bool authed = false;
        bool isbanneduser = false;
        bool firsttime = true;

        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistPeer = true;

        //
        // End of set-up section

        // Start of main loop
        //

        // maintain a persistent connection
        while ((firsttime || persistPeer) && !ttg)
        {
            ldl = o.currentLists();
    HTTPHeader docheader(__HEADER_RESPONSE); // to hold any HTTP response header sent by ICAP client
    HTTPHeader header(__HEADER_REQUEST); // to hold the HTTP request header sent by ICAP client
    ICAPHeader icaphead;
    icaphead.setHTTPhdrs(header, docheader);

            NaughtyFilter checkme(header, docheader);
            DataBuffer docbody;
            docbody.setTimeout(o.exchange_timeout);
            FDTunnel fdt;

            if (firsttime) {
                // reset flags & objects next time round the loop
                firsttime = false;

                // quick trick for the very first connection :-)
            } else {
// another round...
#ifdef DGDEBUG
                std::cout << dbgPeerPort << " -persisting (count " << ++pcount << ")" << std::endl;
                syslog(LOG_ERR, "Served %d requests on this connection so far - ismitm=%d", pcount, ismitm);
                std::cout << dbgPeerPort << " - " << clientip << std::endl;
#endif
                icaphead.reset();
                if (!icaphead.in(&peerconn, true )) {
#ifdef DGDEBUG
                    std::cout << dbgPeerPort << " -Persistent connection closed" << std::endl;
#endif
		// TODO: send error reply if needed
                    break;
                }
                ++dystat->reqs;

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

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

// Check service option REQMOD, RESMOD, OPTIONS and call appropreate function(s)
//
if (icaphead.reqmod && icaphead.icap_reqmod_service) {
    if (handleICAPreqmod() == 0)
        continue;
    else
        break;

} else if (icaphead.resmod && icaphead.icap_resmod_service) {
	// auth ??
	// if reqhdr request SB ?????
	// response SB on res_hdr
	// respond & process body

} else if (icaphead.options && icaphead.icap_reqmod_service) {
	// respond with option response
    String wline = "ICAP/1.0 200 OK\n";
    wline += "Methods: REQMOD\n";
    wline += "Service: e2guardian 5.0\n";
    wline += "ISTag:";
    wline += ldl->ISTag();
     wline += "\n";
    wline += "Encapsulated: null-body=0\n";
    wlien += "Allow: 204\n";
    wlien += "Preview: 0\n";
    wlien += "\n";
    peerconn.writeString(wline.toCharArray());

} else if (icaphead.options && icaphead.icap_resmod_service) {
    // respond with option response
    String wline = "ICAP/1.0 200 OK\n";
    wline += "Methods: RESMOD\n";
    wline += "Service: e2guardian 5.0\n";
    wline += "ISTag:";
    wline += ldl->ISTag();
    wline += "\n";
    wline += "Encapsulated: null-body=0\n";
    wlien += "Allow: 204\n";
    wlien += "Preview: 2048\n";
    wlien += "\n";
    peerconn.writeString(wline.toCharArray());
} else if ((icaphead.reqmod && !icaphead.icap_reqmod_service) || (icaphead.resmod && !icaphead.icap_resmod_service)) {
                String wline = "ICAP/1.0 405 Method not allowed for service\n";
                wline += "Service: e2guardian 5.0\n";
                //wline += "ISTag:";
                //wline += ldl->ISTag();
                //wline += "\n";
                wline += "Encapsulated: null-body=0\n";
                wlien += "\n";
                peerconn.writeString(wline.toCharArray());
            } else {
                //send error response
                String wline = "ICAP/1.0 400 Bad request\n";
                wline += "Service: e2guardian 5.0\n";
                //wline += "ISTag:";
                //wline += ldl->ISTag();
                //wline += "\n";
                wline += "Encapsulated: null-body=0\n";
                wlien += "\n";
                peerconn.writeString(wline.toCharArray());
		};


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
}




int ConnectionHandler::handleICAPreqmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead) {

            // do all of this normalisation etc just the once at the start.
            checkme.setURL();
            String res_hdr, res_body, req_hdr, req_body;

            // checks for bad URLs to prevent security holes/domain obfuscation.
            if (header.malformedURL(checkme.url)) {
                // The requested URL is malformed.
                gen_error_mess(checkme, res_hdr, res_body, 200, 0, "400 Bad Request");
                checkme.isdone = true;
                icaphead.errorResponse(peerconn,res_hdr,res_body);
                return 0;
            }

            // do total block list checking here
            if (o.use_total_block_list && o.inTotalBlockList(checkme.urld)) {
                    res_hdr = "HTTP/1.0 200 OK\n";
                    o.banned_image.display_hb(res_hdr, res_body);
                    icaphead.errorResponse(peerconn,res_hdr,res_body);
                return 0;
                }

            //
            //
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
                if (!doAuth(authed, filtergroup, auth_plugin,  peerconn, proxysock,  header) ) {
                    //break;  // TODO Error return????
                }
                authed = true;
            checkme.filtergroup = filtergroup;

#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -username: " << clientuser << std::endl;
            std::cout << dbgPeerPort << " -filtergroup: " << filtergroup << std::endl;
#endif
//
//
// End of Authentication Checking
//
//


            //
            //
            // Now check if user or machine is banned and room-based checking
            //
            //

            // is this user banned?
            isbanneduser = false;
            if (o.use_xforwardedfor) {
                bool use_xforwardedfor;
                if (o.xforwardedfor_filter_ip.size() > 0) {    // TODO get this instead from Icapheder??
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
            checkme.clientip = clientip;

            // Look up reverse DNS name of client if needed
            if (o.reverse_client_ip_lookups) {
                std::unique_ptr<std::deque<String> > hostnames;
                    hostnames.reset(ipToHostname(clientip.c_str()));
                    checkme.clienthost = std::string(hostnames->front().toCharArray());
            }

            //CALL SB pre-authcheck
            ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH_ICAP, checkme);
            std::cerr << "After StoryA icap-pre-authcheck" << checkme.isexception << " mess_no "
                      << checkme.message_no << std::endl;
            checkme.isItNaughty = checkme.isBlocked;
            bool isbannedip = checkme.isBlocked;
            bool part_banned;
            if (isbannedip) {
               // matchedip = clienthost == NULL;
            } else {
                if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
                                checkme.urld)) {
#ifdef DGDEBUG
                    std::cout << " isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << checkme.isexception << std::endl;
#endif
                    if (isbannedip) {
                 //       matchedip = clienthost == NULL;
                        checkme.isBlocked = checkme.isItNaughty = true;
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



            //
            // Start of by pass
            //  TODO Need ICAP veriosn of checkByPass???
            //if (checkByPass( checkme,  ldl, header,  proxysock, peerconn, clientip, persistProxy)) {
            //    break;
            //}

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
// Main checking is now done in Storyboard function(s)
                    ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_ICAP_REQMOD,checkme);
                    std::cerr << "After StoryB checkreqmod" << checkme.isexception << " mess_no "
                              << checkme.message_no << std::endl;
                    checkme.isItNaughty = checkme.isBlocked;
            }

            //check for redirect
            // URL regexp search and edirect
            if (checkme.urlredirect) {
                checkme.url = header.redirecturl();
                proxysock.close();
                String writestring("HTTP/1.0 302 Redirect\nLocation: ");
                writestring += checkme.url;
                writestring += "\n\n";
                res_hdr = writestring;
                icaphead.errorResponse(peerconn, res_hdr, res_body);
                checkme.done = true;
            }

            //if  is a search - content check search terms
            if ( !checkme.done && checkme.isSearch)
                check_search_terms(checkme);  // will set isItNaughty if needed


            // TODO V5 call POST scanning code New NaughtyFilter function????

            if(checkme.isItNaughty) {
                if(genDenyAccess(res_hdr, res_body, &header, &docheader, &checkme.url, &checkme, &clientuser, &clientip,
                           filtergroup, checkme.ispostblock,checkme.headersent, checkme.wasinfected, checkme.scanerror)) {
                    icaphead.errorResponse(peerconn, res_hdr, res_body);
                    checkme.done = true;
            };

// TODO add logicv for 204 response etc.

                if( !checkme.done)
                    icaphead.respond(peerconn);
            //Log
            if (!checkme.isourwebserver) { // don't log requests to the web server
                doLog(clientuser, clientip, checkme);
            }

}
}


int ConnectionHandler::handleICAPresmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead) {

            // do all of this normalisation etc just the once at the start.
            checkme.setURL();

            // do total block list checking here - checked on REQMOD so not needed for RESMOD

            // don't let the client connection persist if the client doesn't want it to.
            persistOutgoing = header.isPersistent();
            //
            //
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
                if (!doAuth(authed, filtergroup, auth_plugin,  peerconn, proxysock,  header) )
                {
                    // need error checking or just set to default???
                } else {
                    authed = true;
                    checkme.filtergroup = filtergroup;
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
            checkme.clientip = clientip;

            // Look up reverse DNS name of client if needed
            if (o.reverse_client_ip_lookups) {
                std::unique_ptr<std::deque<String> > hostnames;
                    hostnames.reset(ipToHostname(clientip.c_str()));
                    checkme.clienthost = std::string(hostnames->front().toCharArray());
            }

            bool part_banned;



            //
            // Start of by pass - ?Checked in REQMOD not needed in RESMOD
            //

            char *retchar;

            //
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
            if (!(isbanneduser || isbannedip || checkme.isbypass || checkme.isexception)) {
// Main checking is done in Storyboard function(s)
                    ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_ICAP_RESMOD,checkme);
                    std::cerr << "After StoryB icapcheckresmod" << checkme.isexception << " mess_no "
                              << checkme.message_no << std::endl;
                    checkme.isItNaughty = checkme.isBlocked;
            }

            //check for redirect - can't redirect at this stage only at REQMOD
            // URL regexp search and edirect

            // don't run willScanRequest if content scanning is disabled, or on exceptions if contentscanexceptions is off,
            // or on SSL (CONNECT) requests, or on HEAD requests, or if in AV bypass mode

            //now send upstream and get response
            if (!checkme.isItNaughty) {
                std::cout << dbgPeerPort << " -persistPeer: " << persistPeer << std::endl;
#endif
            }


            //check response code
            if (!checkme.isItNaughty) {
                int rcode = docheader.returnCode();
                {
                    checkme.ismitmcandidate = false;  // only applies to connect
                    checkme.tunnel_rest = true;
                    checkme.tunnel_2way = false;
                }
                //TODO check for other codes which do not have content payload make these tunnel_rest.
                if (checkme.isexception)
                    checkme.tunnel_rest = true;
            }

            if(!checkme.isItNaughty ) {
                if (checkme.ishead || docheader.contentLength() == 0)
                    checkme.tunnel_rest = true;
            }

            //- if grey content check
                // can't do content filtering on HEAD or redirections (no content)
                // actually, redirections CAN have content
                if (checkme.isGrey && !checkme.tunnel_rest) {
                    // TODO  function needs adapting to ICAP chunked
                    check_content(checkme, docbody,proxysock, peerconn,responsescanners);
                }

            //send response header to client
            if (!checkme.isItNaughty) {
                // TODO needs revised out for ICAP
                if (!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL, false ))
                    cleanThrow("Unable to send return header to client", peerconn, proxysock);
            }

            if(!checkme.isItNaughty &&checkme.waschecked)  {
                // TODO needs revised out for ICAP
                if(!docbody.out(&peerconn))
                    checkme.pausedtoobig = false;
                if(checkme.pausedtoobig)
                    checkme.tunnel_rest = true;
            }


            //if not grey tunnel response
            if (!checkme.isItNaughty && checkme.tunnel_rest) {
                std::cerr << dbgPeerPort << " -Tunnelling to client" << std::endl;
                if (!fdt.tunnel(proxysock, peerconn,checkme.isconnect, docheader.contentLength() - checkme.docsize, true))
                    persistProxy = false;
                checkme.docsize += fdt.throughput;
            }


#ifdef DGDEBUG
            std::cout << dbgPeerPort << " -Forwarding body to client" << std::endl;
#endif
            if(checkme.isItNaughty) {
                if(genDenyAccess(res_hdr, res_body, &header, &docheader, &checkme.url, &checkme, &clientuser, &clientip,
                           filtergroup, checkme.ispostblock,checkme.headersent, checkme.wasinfected, checkme.scanerror))
                    persistPeer = false;
            }

            //Log
            if (!checkme.isourwebserver) { // don't log requests to the web server
                doLog(clientuser, clientip, checkme);
            }

            return 0;
}
