#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#ifdef __SSLMITM
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>

#include <climits>
#include <string>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "CertificateAuthority.hpp"

//#define printerr(arg) printf("Error \"%s\" in %s at line %d\n", arg, __FILE__ , __LINE__);

CertificateAuthority::CertificateAuthority(const char * caCert,
				const char * caPrivKey, 
				const char * certPrivKey, 
				const char * certPath,
				const char * certLinks)
{
	FILE *fp;
	
	//load the ca cert
	fp = fopen (caCert, "r");
	if (fp == NULL){
		syslog(LOG_ERR,"Couldn't open ca certificate");
		exit(1);
	}
	_caCert = PEM_read_X509(fp, NULL, NULL, NULL);
	if (_caCert == NULL){
		syslog(LOG_ERR,"Couldn't load ca certificate");
		//ERR_print_errors_fp(stderr);
		exit(1);
	}

	fclose (fp);

	//load the ca priv key
	fp = fopen (caPrivKey, "r");
	if (fp == NULL){
		syslog(LOG_ERR,"Couldn't open ca private key");
		exit(1);
	}
	_caPrivKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if (_caPrivKey == NULL){
		syslog(LOG_ERR,"Couldn't load ca private key");
		//ERR_print_errors_fp(stderr);
		exit(1);
	}

	fclose (fp);

	//load the priv key to use with generated certificates
	fp = fopen(certPrivKey, "r");
	if (fp == NULL){
		syslog(LOG_ERR,"Couldn't open certificate private key");
		exit(1);
	}
	_certPrivKey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	
	if (_certPrivKey == NULL){
		syslog(LOG_ERR,"Couldn't load certificate private key");
		//ERR_print_errors_fp(stderr);
		exit(1);
	}
	fclose (fp);
		
	//TODO should check this is a writable dir
	_certPath = certPath;
	_certLinks = certLinks;
}

ASN1_INTEGER * CertificateAuthority::getSerial(const char * commonname){
	//generate hash of hostname
	char cnhash[EVP_MAX_MD_SIZE];
	unsigned int cnhashlen;

#ifdef DGDEBUG
	std::cout << "Generating serial no for " << commonname << std::endl;
#endif

	EVP_MD_CTX mdctx;
	const EVP_MD *md = EVP_md5();
	EVP_MD_CTX_init(&mdctx);
	
	bool failed = false;
	if(!failed && EVP_DigestInit_ex(&mdctx, md, NULL) < 1){
		failed = true;
	}
	
	if(!failed && EVP_DigestUpdate(&mdctx, commonname, strlen(commonname)) < 1){
		failed = true;
	}
	
	if(!failed && EVP_DigestFinal_ex(&mdctx,(unsigned char *) cnhash, &cnhashlen) <1){
		failed = true;
	}

	EVP_MD_CTX_cleanup(&mdctx);

	if(failed){
		return NULL;
	}
	
	//convert to asn1 to use as serial 
	BIGNUM * bn = BN_bin2bn((const unsigned char *)cnhash,cnhashlen,NULL);
	
	if(bn == NULL){
		return NULL;
	}
	
#ifdef DGDEBUG
	char * dbg = BN_bn2hex(bn);
	if (dbg != NULL)
	{
		std::cout << "Serial no is " << dbg << std::endl;
	}
	else
	{
		std::cout << "bn2hex returned null instead of serial number" << std::endl;
	}
	OPENSSL_free(dbg);
#endif

	ASN1_INTEGER* serialNo = BN_to_ASN1_INTEGER(bn,NULL);


	BN_free(bn);
	return serialNo;
}

//write a certificate to disk being careful to avoid race conditions.
//returns true if it already existed or false on error
//common name (sh/c)ould be derived from the certificate but that would add to the complexity of the code
bool CertificateAuthority::writeCertificate(const char * commonname, X509 * newCert)
{	
	//<TODO>getSerial change to pulling serial from cert
	ASN1_INTEGER* aserial = getSerial(commonname);
	BIGNUM* bserial = ASN1_INTEGER_to_BN(aserial,NULL);
	char * cserial = BN_bn2hex(bserial);
	std::string filename(cserial);
	OPENSSL_free(cserial);
	BN_free(bserial);
	ASN1_INTEGER_free(aserial);
	
	
	//open file
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	int fd = open((_certPath + filename).c_str(), O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH );

#ifdef DGDEBUG 
	std::cout << "certificate file is " << _certPath << filename << std::endl;
#endif
	if (fd < 0){
		syslog(LOG_ERR,"error opening new certificate");
		exit(1);
	}
	
	//lock file with blocking lock and see if its bigger than 0 bytes
	if(fcntl(fd, F_SETLKW, &fl) < 0){
		close(fd);
		return false;
	}
	
	off_t pos = lseek(fd,0,SEEK_END);	

	//check if someone else created the file before we did (avoid the race condition)
	if (pos < 0){
#ifdef DGDEBUG
		std::cout << "error seeking to find certificate size " << std::endl;
#endif
		fl.l_type = F_UNLCK;
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		return false;
	}
	else if (pos > 0){
		//didnt get first lock so cert should be there now
#ifdef DGDEBUG
		std::cout << "didnt get first lock pos was " << pos << std::endl;
#endif
		fl.l_type = F_UNLCK;
		fcntl(fd, F_SETLK, &fl);
		close(fd);
		return true;
	}

	//looks like we got the first lock so write the certificate
	//write the cert to a file
#ifdef DGDEBUG
	std::cout << "got first lock " << std::endl;
#endif
	FILE * fp = fdopen(fd, "w");
	if (fp==NULL){
		fclose(fp);
		return false;
	}
	
	if(PEM_write_X509(fp, newCert) < 1){
		fclose(fp);
		return false;
	}
	
	if (fflush(fp) == EOF){
		fclose(fp);
		return false;
	}
	
	if (fsync(fd) < 0){
		fclose(fp);
		return false;
	}

	if(symlink((_certPath + filename).c_str(),
		(_certLinks + filename).c_str()) < 0){
		syslog(LOG_ERR,"couldnt create link to certificate");
		fclose(fp);
		exit(1);
	}
		
	//unlock the file
	fl.l_type = F_UNLCK;
	fcntl(fd, F_SETLK, &fl);
	fclose(fp);
	close(fd);
	return true;
}

//generate a certificate for a given hostname
X509 * CertificateAuthority::generateCertificate(const char * commonname){
	//create a blank cert
	X509 *newCert=X509_new();
	if (newCert == NULL){
		return NULL;
	}
	
	if(X509_set_version(newCert, 2) < 1){
		X509_free(newCert);
		return NULL;
	}
	
	//set a serial on the cert
	ASN1_INTEGER* serialNo = getSerial(commonname);
	if (serialNo == NULL){
		X509_free(newCert);
		return NULL;
	}

	if(X509_set_serialNumber(newCert, serialNo) < 1){
		X509_free(newCert);
		ASN1_INTEGER_free(serialNo);
		return NULL;
	}
	
	ASN1_INTEGER_free(serialNo);
	
	//set valid from and expires dates
	//from yesterday
	if (!ASN1_TIME_set(X509_get_notBefore(newCert), time(NULL) - 86400)){
		X509_free(newCert);
		return NULL;
	}
	
	if(!ASN1_TIME_set(X509_get_notAfter(newCert), time(NULL) + 315532800)){
		X509_free(newCert);
		return NULL;	
	}//to 10 years from now


	//set the public key of the new cert
	//the private key data type also contains the pub key which is used below.
	if(X509_set_pubkey(newCert, _certPrivKey) < 1){
		X509_free(newCert);
		return NULL;	
	}

	//create a name section
	X509_NAME *name=X509_get_subject_name(newCert);
	if (name == NULL){
		X509_free(newCert);
		return NULL;
	}
	
	//add the cn of the site we want a cert for the destination
	int rc = X509_NAME_add_entry_by_txt(name,"CN",
		MBSTRING_ASC, (unsigned char *)commonname, -1, -1, 0);


	if (rc < 1){
		X509_NAME_free(name);
		X509_free(newCert);
		return NULL;	
	}
	
	//set the issuer name of the cert to the cn of the ca	
	X509_NAME* subjectName = X509_get_subject_name(_caCert);
	if (subjectName == NULL){
		X509_free(newCert);
		return NULL;		
	}
	
	
	if(X509_set_issuer_name(newCert, subjectName) < 1){
		X509_NAME_free(subjectName);
		X509_free(newCert);
		return NULL;
	}
	
	//sign it using the ca
	if (!X509_sign(newCert, _caPrivKey, EVP_sha1())){
		X509_free(newCert);
		return NULL;
	}

#ifdef DGDEBUG
        std::cout << "certificate create " << name << std::endl;
#endif
	
	return newCert;
}

//sets cert to the certificate for commonname
//returns true if the cert was loaded from cache / false if it was generated
bool CertificateAuthority::getServerCertificate(const char * commonname,X509** cert){
	
	ASN1_INTEGER* aserial = getSerial(commonname);
	BIGNUM* bserial = ASN1_INTEGER_to_BN(aserial,NULL);
	char * cserial = BN_bn2hex(bserial);
	std::string filename(cserial);
	OPENSSL_free(cserial);
	BN_free(bserial);
	ASN1_INTEGER_free(aserial);

#ifdef DGDEBUG
        std::cout << "looking for cert " << _certLinks << filename << std::endl;
#endif
	//check to see if there is a symlink to the file
	std::string path(_certLinks + filename);
	FILE* link = fopen(path.c_str(),"r");

	if (link != NULL){
#ifdef DGDEBUG
		std::cout << "Certificate found" << std::endl;
#endif

		//if there was then the certificate has already been created
		*cert = PEM_read_X509(link, NULL, NULL, NULL);

		fclose(link);

		//dont need to check the return as this returns null if it couldnt load a cert
		return true;
	}
	else {
#ifdef DGDEBUG
	std::cout << "Certificate not found. Creating one" << std::endl;
#endif

	//generate a certificate
	 *cert = generateCertificate(commonname);
	return false;
	}
}

EVP_PKEY* CertificateAuthority::getServerPkey(){
	//openssl is missing a EVP_PKEY_dup function so just up the ref count
	//see http://www.mail-archive.com/openssl-users@openssl.org/msg17614.html
	CRYPTO_add(&_certPrivKey->references,1,CRYPTO_LOCK_EVP_PKEY);
	return _certPrivKey;	
}

CertificateAuthority::~CertificateAuthority(){
	X509_free(_caCert);
	EVP_PKEY_free(_caPrivKey);
	EVP_PKEY_free(_certPrivKey);
}
#endif //__SSLMITM
