// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_URLREC
#define __HPP_URLREC

// INCLUDES

struct url_rec {
    String fullurl;
    String urldomain;
    String baseurl;
    bool is_siteonly = false;
    bool site_is_ip = false;
};
#endif

