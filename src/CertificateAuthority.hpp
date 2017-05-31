#ifndef __HPP_CERTIFICATEAUTHORITY
#define __HPP_CERTIFICATEAUTHORITY
#ifdef __SSLMITM

struct ca_serial {
    ASN1_INTEGER *asn;
    char *charhex;
    char *filepath;
    char *filename;
};

void log_ssl_errors( const char *mess, const char *site);

class CertificateAuthority
{

    protected:
    EVP_PKEY *_caPrivKey;
    EVP_PKEY *_certPrivKey;
    X509 *_caCert;
    std::string _certPath;
    int _certPathLen;
    std::string _certLinks;
    time_t _ca_start;
    time_t _ca_end;
    static int do_mkdir(const char *path, mode_t mode);
    int mkpath(const char *path, mode_t mode);
    bool addExtension(X509 *cert, int nid, char *value);

    public:
    CertificateAuthority(const char *caCert,
        const char *caPrivKey,
        const char *certPrivKey,
        const char *certPath,
        time_t caStart,
        time_t caEnd);

    ~CertificateAuthority();
    X509 *generateCertificate(const char *commonname, struct ca_serial *cser);
    bool getSerial(const char *commonname, struct ca_serial *cser);
    bool getServerCertificate(const char *commonname, X509 **cert, struct ca_serial *cser);
    bool writeCertificate(const char *hostname, X509 *newCert, struct ca_serial *cser);
    EVP_PKEY *getServerPkey();
    bool free_ca_serial(struct ca_serial *cs);
};

#endif //__SSLMITM

#endif //__HPP_CERTIFICATEAUTHORITY
