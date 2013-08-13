#ifndef __HPP_CERTIFICATEAUTHORITY
#define __HPP_CERTIFICATEAUTHORITY
#ifdef __SSLMITM

class CertificateAuthority {

protected:
	
	EVP_PKEY * _caPrivKey;
	EVP_PKEY * _certPrivKey;
	X509 * _caCert;
	std::string _certPath;
	std::string _certLinks;

public:
	CertificateAuthority(const char * caCert,
				const char * caPrivKey,
				const char * certPrivKey, 
				const char * certPath,
				const char * symlinkPath);

	~CertificateAuthority();
	X509 * generateCertificate(const char * commonname);
	ASN1_INTEGER * getSerial(const char * commonname);
	bool getServerCertificate(const char * commonname, X509** cert);
	bool writeCertificate(const char * hostname, X509 * newCert);
	EVP_PKEY * getServerPkey();
};

#endif //__SSLMITM

#endif //__HPP_CERTIFICATEAUTHORITY

