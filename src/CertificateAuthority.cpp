#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <climits>
#include <string>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "CertificateAuthority.hpp"
#include "OptionContainer.hpp"
#include "Logger.hpp"

extern OptionContainer o;

void log_ssl_errors(const char *mess, const char *site) {
    //E2LOGGER_debugnet(mess, site);
    if( o.logger.log_ssl_errors ) {
        E2LOGGER_error("SSL Error: ", mess, " at: ", site);
        unsigned long e;
        char buff[512];
        while ((e = ERR_get_error())) {
            ERR_error_string(e, &buff[0]);
            E2LOGGER_error("SSL Error: ", buff, " at: ", site);
        }
    }
}

CertificateAuthority::CertificateAuthority(const char *caCert,
    const char *caPrivKey,
    const char *certPrivKey,
    const char *certPath,
    time_t caStart,
    time_t caEnd)
{
    FILE *fp;
    char pem[7200];

    //load the ca cert
    fp = fopen(caCert, "r");
    if (fp == NULL) {
        E2LOGGER_error("Couldn't open ca certificate file ", caCert);
        exit(1);
    }
    _caCert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (_caCert == NULL) {
        log_ssl_errors("Couldn't load ca certificate from ",  caCert);
        exit(1);
    }
    fclose(fp);

    // open again to get raw PEM for hash
    fp = fopen(caCert, "r");
    for (int i = 0;i < 7200;i++) {
        pem[i] = '\0';
    }
    int rc = 0;
    rc = fread(pem,72,99,fp);
    if(rc < 1) {
        E2LOGGER_error("Unable to re-read ca certificate file");
        exit(1);
    }
    fclose(fp);

    //load the ca priv key
    fp = fopen(caPrivKey, "r");
    if (fp == NULL) {
        E2LOGGER_error("Couldn't open ca private key");
        exit(1);
    }
    _caPrivKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (_caPrivKey == NULL) {
        E2LOGGER_error("Couldn't load ca private key");
        exit(1);
    }

    fclose(fp);

    //load the priv key to use with generated certificates
    fp = fopen(certPrivKey, "r");
    if (fp == NULL) {
        E2LOGGER_error("Couldn't open certificate private key");
        exit(1);
    }
    _certPrivKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    if (_certPrivKey == NULL) {
        E2LOGGER_error("Couldn't load certificate private key");
        exit(1);
    }
    fclose(fp);

    //TODO should check this is a writable dir
    _certPath = certPath;
    _certPathLen = sizeof(certPath);
    _certLinks = certPath; // temp to check if this works
    _ca_start = caStart;
    _ca_end = caEnd;

    // Generate hash to be added to cert server name to produce serial unique rootCA_PEM/start_date/stop_date

//   ASN1_TIME *not_before = X509_get_notBefore(_caCert);
//   ASN1_TIME *not_after = X509_get_notAfter(_caCert);

     // Make hash
     String tem = pem;
     String tem2((long)caStart), tem3((long)caEnd);
     tem += tem2;
     tem += tem3;
     cert_start_stop_hash = tem.md5();
     DEBUG_config("modifing string to be hashed (rootCA.pem + cartstart + certend is: ", tem);
     DEBUG_config("modifing hash is: ", cert_start_stop_hash);
}

bool CertificateAuthority::getSerial(const char *commonname, struct ca_serial *caser)
{
    //generate hash of hostname
    char cnhash[EVP_MAX_MD_SIZE];
    unsigned int cnhashlen;

    std::string sname(commonname );
    sname += cert_start_stop_hash;

    DEBUG_debug("Generating serial no for ", commonname );

    EVP_MD_CTX *mdctx;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "openssl version 1.1 or greater is required"
#endif
    mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    EVP_MD_CTX_init(mdctx);

    bool failed = false;
    if (!failed && EVP_DigestInit_ex(mdctx, md, NULL) < 1) {
        failed = true;
    }

    if (!failed && EVP_DigestUpdate(mdctx, sname.c_str(), strlen(sname.c_str())) < 1) {
        failed = true;
    }

    if (!failed && EVP_DigestFinal_ex(mdctx, (unsigned char *)cnhash, &cnhashlen) < 1) {
        failed = true;
    }

    EVP_MD_CTX_free(mdctx);

    if (failed) {
        return false;
    }

    //convert to asn1 to use as serial
    BIGNUM *bn = BN_bin2bn((const unsigned char *)cnhash, cnhashlen, NULL);

    if (bn == NULL) {
        return false;
    }

    char *dbg = BN_bn2hex(bn);
    if (dbg != NULL) {
        DEBUG_debug("Serial no is ", dbg);
    } else {
        DEBUG_debug("bn2hex returned null instead of serial number");
    }
    caser->charhex = dbg;
    caser->asn = BN_to_ASN1_INTEGER(bn, NULL);
    BN_free(bn);
    return true;
}

//write a certificate to disk being careful to avoid race conditions.
//returns true if it already existed or false on error
//common name (sh/c)ould be derived from the certificate but that would add to the complexity of the code
bool CertificateAuthority::writeCertificate(const char *commonname, X509 *newCert, struct ca_serial *caser)
{
    std::string path(caser->filename);
    std::string dirpath(caser->filepath);

    // make directory path
    int rc = mkpath(dirpath.c_str(), 0700); // only want e2g to have access to these dir
    if (rc != 0) {
        E2LOGGER_error("error creating certificate sub-directory: ", dirpath);
        return false; 
    }

    //open file
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = getpid();

    DEBUG_debug("certificate file is ",path);
    int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IWUSR | S_IRUSR); //only e2g has access
    if (fd < 0) {
        E2LOGGER_error("error opening new certificate");
        exit(1);
    }

    //lock file with blocking lock and see if its bigger than 0 bytes
    if (fcntl(fd, F_SETLKW, &fl) < 0) {
        close(fd);
        return false;
    }

    off_t pos = lseek(fd, 0, SEEK_END);

    //check if someone else created the file before we did (avoid the race condition)
    if (pos < 0) {
        DEBUG_debug("error seeking to find certificate size ");
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
        return false;
    } else if (pos > 0) {
        //didnt get first lock so cert should be there now
        DEBUG_debug("didnt get first lock pos was ", pos);
        fl.l_type = F_UNLCK;
        fcntl(fd, F_SETLK, &fl);
        close(fd);
        return true;
    }

    //looks like we got the first lock so write the certificate
    //write the cert to a file
    DEBUG_debug("got first lock ");
    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        return false;
    }

    if (PEM_write_X509(fp, newCert) < 1) {
        fclose(fp);
        return false;
    }

    if (fflush(fp) == EOF) {
        fclose(fp);
        return false;
    }

    if (fsync(fd) < 0) {
        fclose(fp);
        return false;
    }

    //unlock the file
    fl.l_type = F_UNLCK;
    fcntl(fd, F_SETLK, &fl);
    fclose(fp);
    close(fd);
    return true;
}

//generate a certificate for a given hostname
X509 *CertificateAuthority::generateCertificate(const char *commonname, struct ca_serial *cser, bool is_ip)
{
    //create a blank cert
    ERR_clear_error();
    X509 *newCert = X509_new();
    if (newCert == NULL) {
        log_ssl_errors("new blank cert failed for %s", commonname);
        return NULL;
    }

    ERR_clear_error();
    if (X509_set_version(newCert, 2) < 1) {
        log_ssl_errors("set_version on cert failed for %s", commonname);
        X509_free(newCert);
        return NULL;
    }

    //set a serial on the cert
    ERR_clear_error();
    if (X509_set_serialNumber(newCert, (cser->asn)) < 1) {
        log_ssl_errors("set_serialNumber on cert failed for %s", commonname);
        X509_free(newCert);
        return NULL;
    }

    //set valid from and expires dates
    // now from fixed date - should ensure regenerated certs are same and that servers in loadbalanced arrary give same cert
    if (!ASN1_TIME_set(X509_get_notBefore(newCert), _ca_start)) {
        DEBUG_debug("get_notBefore on cert failed for ", commonname );
        X509_free(newCert);
        return NULL;
    }

    if (!ASN1_TIME_set(X509_get_notAfter(newCert), _ca_end)) {
        DEBUG_debug("get_notAfter on cert failed for ", commonname);
        X509_free(newCert);
        return NULL;
    }

    //set the public key of the new cert
    //the private key data type also contains the pub key which is used below.
    ERR_clear_error();
    if (X509_set_pubkey(newCert, _certPrivKey) < 1) {
        log_ssl_errors("set_pubkey on cert failed for %s", commonname);
        X509_free(newCert);
        return NULL;
    }

    //create a name section
    ERR_clear_error();
    X509_NAME *name = X509_get_subject_name(newCert);
    if (name == NULL) {
        log_ssl_errors("get_subject_name on cert failed for %s", commonname);
        X509_free(newCert);
        return NULL;
    }

    //add the cn of the site we want a cert for the destination
    ERR_clear_error();
    int rc = X509_NAME_add_entry_by_txt(name, "CN",
        MBSTRING_ASC, (unsigned char *)commonname, -1, -1, 0);

    if (rc < 1) {
        log_ssl_errors("NAME_add_entry_by_txt on cert failed for %s", commonname);
    //    X509_NAME_free(name);
        X509_free(newCert);
        return NULL;
    }

    //set the issuer name of the cert to the cn of the ca
    ERR_clear_error();
    X509_NAME *subjectName = X509_get_subject_name(_caCert);
    if (subjectName == NULL) {
        log_ssl_errors("get_subject_name on ca_cert failed for %s", commonname);
        X509_free(newCert);
        return NULL;
    }

    ERR_clear_error();
    if (X509_set_issuer_name(newCert, subjectName) < 1) {
        log_ssl_errors("set_issuer_name on cert failed for %s", commonname);
     //   X509_NAME_free(subjectName);
        X509_free(newCert);
        return NULL;
    }

    String temp1;

   // E2LOGGER_error("common name is ",commonname);
    String temp2 = commonname;
    if(temp2.contains(":")) {
        bool not_first_one = false;
        temp2 += ":";
  //      E2LOGGER_error("temp2 is ",temp2);
        while (!temp2.empty()) {
            String temp3 = temp2.before(":");
            temp2 = temp2.after(":");
            if (not_first_one) {
                temp1 += ", ";
            }
            not_first_one = true;
            if (temp3.isIp())
                temp1 += "IP:";
            else
                temp1 += "DNS:";
            temp1 += temp3;
        }
 //       E2LOGGER_error("alt_name string is ",temp1);
        char    *value = (char*) temp1.toCharArray();
        if( !addExtension(newCert, NID_subject_alt_name, value))
            log_ssl_errors("Error adding subjectAltName to the request", commonname);

    } else {
        if (is_ip)
            temp1 = "IP:";
        else
            temp1 = "DNS:";
    temp1 += temp2;
//        E2LOGGER_error("alt_name string is ",temp1);
    char    *value = (char*) temp1.toCharArray();
     if( !addExtension(newCert, NID_subject_alt_name, value))
        log_ssl_errors("Error adding subjectAltName to the request", commonname);
     }


    //sign it using the ca
    ERR_clear_error();
    if (!X509_sign(newCert, _caPrivKey, EVP_sha256())) {
        log_ssl_errors("X509_sign on cert failed for %s", commonname);
        X509_free(newCert);
        return NULL;
    }

    DEBUG_debug("certificate create ", name );

    return newCert;
}

//sets cert to the certificate for commonname
//returns true if the cert was loaded from cache / false if it was generated
bool CertificateAuthority::getServerCertificate(const char *commonname, X509 **cert, struct ca_serial *caser, bool is_ip)
{

    getSerial(commonname, caser);
    std::string filename(caser->charhex);

    // Generate directory path
    std::string subpath(filename.substr(0, 2) + '/' + filename.substr(2, 2)
        + '/' + filename.substr(4, 2) + '/');
    std::string filepath(_certLinks + subpath);
    std::string path(_certLinks + subpath + filename.substr(6));
    caser->filepath = strdup(filepath.c_str());
    caser->filename = strdup(path.c_str());

    DEBUG_debug("looking for cert ", path);
    //check to see if there is a symlink to the file
    //	std::string path(_certLinks + filename);
    FILE *link = fopen(path.c_str(), "r");

    if (link != NULL) {
        DEBUG_debug("Certificate found");

        //if there was then the certificate has already been created
        *cert = PEM_read_X509(link, NULL, NULL, NULL);

        fclose(link);

        //dont need to check the return as this returns null if it couldnt load a cert
        return true;
    } else {
        DEBUG_debug("Certificate not found. Creating one");

        //generate a certificate
        *cert = generateCertificate(commonname, caser, is_ip);
        return false;
    }
}

EVP_PKEY *CertificateAuthority::getServerPkey()
{
    EVP_PKEY_up_ref(_certPrivKey);
    return _certPrivKey;
}

int CertificateAuthority::do_mkdir(const char *path, mode_t mode)
{
    struct stat st;
    int status = 0;

    if (stat(path, &st) != 0) {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    } else if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        status = -1;
    }

    return (status);
}

// mkpath - ensure  all sub-directories in path exist
int CertificateAuthority::mkpath(const char *path, mode_t mode)
{
    char *pp;
    char *sp;
    int status;
    char *copypath = strdup(path);

    status = 0;
    pp = copypath + _certPathLen; //start checking within generated cert directory
    while (status == 0 && (sp = strchr(pp, '/')) != 0) {
        if (sp != pp) {
            *sp = '\0';
            status = do_mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }
    if (status == 0)
        status = do_mkdir(path, mode);
    free(copypath);
    return (status);
}

bool CertificateAuthority::free_ca_serial(struct ca_serial *cs)
{
    if (cs->asn != NULL)
        ASN1_INTEGER_free(cs->asn);
    if (cs->charhex != NULL)
        OPENSSL_free(cs->charhex);
    //	free(cs->charhex);
    if (cs->filepath != NULL)
        free(cs->filepath);
    if (cs->filename != NULL)
        free(cs->filename);
    return true;
}

CertificateAuthority::~CertificateAuthority()
{
    if (_caCert) X509_free(_caCert);
    if (_caPrivKey) EVP_PKEY_free(_caPrivKey);
    if (_certPrivKey) EVP_PKEY_free(_certPrivKey);
}

bool CertificateAuthority::addExtension(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex = NULL;

    ex = X509V3_EXT_conf_nid(NULL,NULL , nid, value);

    int result = X509_add_ext(cert, ex, -1);

    X509_EXTENSION_free(ex);

    return (result > 0) ? true : false;
}

//String CertificateAuthority::ASN1TIME2String(ASN1_TIME *atime)
//{

//};
