int ConnectionHandler::handleICAPreqmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead,
                                        AuthPlugin *auth_plugin) {
    bool authed = false;
    String clientip = ip;
    // do all of this normalisation etc just the once at the start.
    checkme.setURL();
    String res_hdr, res_body, req_hdr, req_body;

    // checks for bad URLs to prevent security holes/domain obfuscation.
    if (icaphead.HTTPrequest->malformedURL(checkme.url)) {
        // The requested URL is malformed.
        gen_error_mess(peerconn, checkme, res_hdr, res_body, 200, 0, "400 Bad Request");
        checkme.isdone = true;
        icaphead.errorResponse(peerconn, res_hdr, res_body);
        if (icaphead.req_body_flag)
            peerconn.drainChunk(peerconn.getTimeout());   // drains body
        return 0;
    }

    // do total block list checking here
    if (o.use_total_block_list && o.inTotalBlockList(checkme.urld)) {
        res_hdr = "HTTP/1.0 200 OK\n";
        o.banned_image.display_hb(res_hdr, res_body);
        icaphead.errorResponse(peerconn, res_hdr, res_body);
        if (icaphead.req_body_flag)
            peerconn.drainChunk(peerconn.getTimeout());   // drains body
        return 0;
    }

    //
    //
    // Start of Authentication Checks
    //
    //
    // don't have credentials for this connection yet? get some!
    overide_persist = false;
    filtergroup = o.default_icap_fg;

    int rc = DGAUTH_NOUSER;
    if(clientuser != "") {
        rc = determineGroup(clientuser, filtergroup, ldl->filter_groups_list);
    }
    if (rc != DGAUTH_OK) {
            if (!doAuth(authed, filtergroup, auth_plugin, peerconn, *icaphead.HTTPrequest, true)) {
                //break;  // TODO Error return????
            }
    }

    authed = true;
    checkme.filtergroup = filtergroup;

#ifdef DGDEBUG
    std::cout << dbgPeerPort << " ICAP -username: " << clientuser << std::endl;
    std::cout << dbgPeerPort << " ICAP -filtergroup: " << filtergroup << std::endl;
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
    bool isbanneduser = false;
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
#ifdef NOTDEF
        if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
                        checkme.urld)) {
#ifdef DGDEBUG
            std::cout << "ICAP isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << checkme.isexception << std::endl;
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
#endif
    }



    //
    // Start of by pass
    //  TODO Need ICAP veriosn of checkByPass???
 /*   if (checkByPass( checkme,  ldl, header,  proxysock, peerconn, clientip, persistProxy)) {
        break;
    }
*/
    //
    // End of scan by pass
    //

    char *retchar;
    bool done = false;

    //
    // Start of exception checking
    //
    // being a banned user/IP overrides the fact that a site may be in the exception lists
    // needn't check these lists in bypass modes
    if (!(isbanneduser || isbannedip || checkme.isbypass || checkme.isexception)) {
// Main checking is now done in Storyboard function(s)
        ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_ICAP_REQMOD, checkme);
        std::cerr << "After StoryB checkreqmod" << checkme.isexception << " mess_no "
                  << checkme.message_no << " allow_204 : " << icaphead.allow_204 << std::endl;
        checkme.isItNaughty = checkme.isBlocked;
    }

// TODO add logicv for 204 response etc.
    if (checkme.isexception) {
        icaphead.set_icap_com(clientuser,"E", filtergroup);
        if (icaphead.allow_204) {
            icaphead.respond(peerconn, "204 No Content");
            if (icaphead.req_body_flag)
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            done = true;
        } else {
            // pipe through headers and body
            icaphead.respond(peerconn, "200 OK", true);
            if (icaphead.req_body_flag)
                peerconn.loopChunk(peerconn.getTimeout());   // echos any body
            done = true;
        }
    }

    //check for redirect
    // URL regexp search and edirect
    if (checkme.urlredirect) {
        checkme.url = icaphead.HTTPrequest->redirecturl();
        String writestring("HTTP/1.0 302 Redirect\nLocation: ");
        writestring += checkme.url;
        writestring += "\n\n";
        res_hdr = writestring;
        icaphead.errorResponse(peerconn, res_hdr, res_body);
        if (icaphead.req_body_flag)
            peerconn.drainChunk(peerconn.getTimeout());   // drains any body
        done = true;
    }

    //if  is a search - content check search terms
    if (!done && checkme.isSearch)
        check_search_terms(checkme);  // will set isItNaughty if needed


    // TODO V5 call POST scanning code New NaughtyFilter function????

    if (checkme.isItNaughty) {
        if (genDenyAccess(peerconn, res_hdr, res_body, icaphead.HTTPrequest, icaphead.HTTPresponse,
                          &checkme.url, &checkme, &clientuser, &clientip,
                          filtergroup, checkme.ispostblock, checkme.headersent, checkme.wasinfected,
                          checkme.scanerror)) {
            icaphead.errorResponse(peerconn, res_hdr, res_body);
            if (icaphead.req_body_flag)
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            done = true;
#ifdef DGDEBUG
            std::cout << "ICAP Naughty" << std::endl;
#endif
	// break loop "// maintain a persistent connection"
   	   return 1;
        };
    }


    if (!done) {
        icaphead.set_icap_com(clientuser,"G", filtergroup);
        icaphead.respond(peerconn, "200 OK", true);
        if (icaphead.req_body_flag)
            peerconn.loopChunk(peerconn.getTimeout());   // echoes any body
    }
    //Log
    if (!checkme.isourwebserver) { // don't log requests to the web server  //TODO should only log blocks here - rest logged by RESPMOD
        doLog(clientuser, clientip, checkme);
    }
    return 0;
}
