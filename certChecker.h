#ifndef CERT_CHECKER_H
#define CERT_CHECKER_H

/**
 * \enum certType
 * \brief type de fichier source
 */
enum certType {
    PEM,    /*! < fichier char pem */
    DER     /*! < fichier binaire der */
};
void loadCa(const char *ca,int size, int type);
void loadCrl(const char *crl,int size, int type);
int checkCert(const char *cert,int size, int type);
void freeStore();

#endif // CERT_CHECKER_H