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
				time_t caStart,
				time_t caEnd)
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
	_certPathLen = sizeof(certPath);
//	_certLinks = certLinks;
	_certLinks = certPath;  // temp to check if this works
	//_ca_start = 1417872951;  // 6th Dec 2014
	//_ca_end = _ca_start + 315532800;  // 6th Dec 2024
	_ca_start = caStart;
	_ca_end = caEnd;
}

bool CertificateAuthority::getSerial(const char * commonname, struct ca_serial* caser){
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
		return false;
	}
	
	//convert to asn1 to use as serial 
	BIGNUM * bn = BN_bin2bn((const unsigned char *)cnhash,cnhashlen,NULL);
	
	if(bn == NULL){
		return false;
	}
	
	char * dbg = BN_bn2hex(bn);
#ifdef DGDEBUG
	if (dbg != NULL)
	{
		std::cout << "Serial no is " << dbg << std::endl;
	}
	else
	{
		std::cout << "bn2hex returned null instead of serial number" << std::endl;
	}
#endif
	caser->charhex = dbg;
	caser->asn = BN_to_ASN1_INTEGER(bn,NULL);
	BN_free(bn);
	return true;
}

//write a certificate to disk being careful to avoid race conditions.
//returns true if it already existed or false on error
//common name (sh/c)ould be derived from the certificate but that would add to the complexity of the code
bool CertificateAuthority::writeCertificate(const char * commonname, X509 * newCert, struct ca_serial* caser)
{	
	std::string path(caser->filename);
	std::string dirpath(caser->filepath);
	
	// make directory path
	mode_t mask = umask(S_IRWXU | S_IRWXG | S_IRWXO);
	int rc = mkpath(dirpath.c_str(), mask);
        if (rc != 0) {
		syslog(LOG_ERR,"error creating certificate sub-directory");
		exit(1);
	}
	
	//open file
	struct flock fl;
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH );

#ifdef DGDEBUG 
	std::cout << "certificate file is " << path  << std::endl;
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
// Symlinks no longer used
	//if(symlink((_certPath + filename).c_str(),
		//(_certLinks + filename).c_str()) < 0){
		//syslog(LOG_ERR,"couldnt create link to certificate");
		//fclose(fp);
		//exit(1);
	//}
		
	//unlock the file
	fl.l_type = F_UNLCK;
	fcntl(fd, F_SETLK, &fl);
	fclose(fp);
	close(fd);
	return true;
}

//generate a certificate for a given hostname
X509 * CertificateAuthority::generateCertificate(const char * commonname, struct ca_serial* cser){
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
	if(X509_set_serialNumber(newCert, (cser->asn)) < 1){
		X509_free(newCert);
		return NULL;
	}
	
	
	//set valid from and expires dates
// now from fixed date - should ensure regenerated certs are same and that servers in loadbalanced arrary give same cert
	if (!ASN1_TIME_set(X509_get_notBefore(newCert), _ca_start)){
		X509_free(newCert);
		return NULL;
	}
	
	if(!ASN1_TIME_set(X509_get_notAfter(newCert), _ca_end)){
		X509_free(newCert);
		return NULL;	
	}


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
bool CertificateAuthority::getServerCertificate(const char * commonname,X509** cert, struct ca_serial* caser ){
	
	getSerial(commonname, caser);
	std::string filename(caser->charhex);

// Generate directory path
	std::string subpath(filename.substr(0,2) + '/' + filename.substr(2,2) 
		+ '/' + filename.substr(4,2) + '/');
	std::string filepath(_certLinks + subpath);
	std::string path(_certLinks + subpath + filename.substr(6));
	caser->filepath = strdup(filepath.c_str());
	caser->filename = strdup(path.c_str());

#ifdef DGDEBUG
        std::cout << "looking for cert " << path << std::endl;
#endif
	//check to see if there is a symlink to the file
//	std::string path(_certLinks + filename);
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
	 *cert = generateCertificate(commonname, caser);
	return false;
	}
}

EVP_PKEY* CertificateAuthority::getServerPkey(){
	//openssl is missing a EVP_PKEY_dup function so just up the ref count
	//see http://www.mail-archive.com/openssl-users@openssl.org/msg17614.html
	CRYPTO_add(&_certPrivKey->references,1,CRYPTO_LOCK_EVP_PKEY);
	return _certPrivKey;	
}

int CertificateAuthority::do_mkdir(const char *path, mode_t mode)
{
    struct stat st;
    int status = 0;

    if (stat(path, &st) != 0)
    {
        mode_t process_mask = umask(0);
        int rc = mkdir(path, mode);
        umask(process_mask);
        
        /* Directory does not exist. EEXIST for race condition */
        if (rc != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}

// mkpath - ensure  all sub-directories in path exist
int CertificateAuthority::mkpath(const char *path, mode_t mode)
{
    char           *pp;
    char           *sp;
    int             status;
    char           *copypath = strdup(path);

    status = 0;
    pp = copypath + _certPathLen;  //start checking within generated cert directory
    while (status == 0 && (sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
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

bool CertificateAuthority::free_ca_serial(struct ca_serial* cs){
	ASN1_INTEGER_free(cs->asn);
	OPENSSL_free(cs->charhex);
//	free(cs->charhex);
	if (cs->filepath != NULL) free(cs->filepath);
	if (cs->filename != NULL) free(cs->filename);
	return true;
}


CertificateAuthority::~CertificateAuthority(){
	X509_free(_caCert);
	EVP_PKEY_free(_caPrivKey);
	EVP_PKEY_free(_certPrivKey);
}
#endif //__SSLMITM
