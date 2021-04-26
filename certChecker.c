/**
 * \file certChecker.c
 * \brief module verification de certificat
 * \author Idriss
 * \version 0.1
 * \date 30 mars 2021
 * 
 * le module expose les fonctions suivantes:
 * void loadCa(const char *ca,int size, int type);
 * void loadCrl(const char *crl,int size, int type);
 * int checkCert(const char *cert,int size, int type);
 * void freeStore();
 */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "certChecker.h"

static int checkCrlIssuer(X509_CRL *xCrl, X509 *xca);
static X509 *buffTox509Cert(const char *certBuf, int size, int type);
static X509_CRL *buffTox509Crl(const char *crlBuf, int size, int type);
static char *asn1_time_to_buff(const ASN1_TIME *time);
static char *usages(X509 *cert);
static void printCert(X509 *cert);
static int check(X509 *x);
void initStore();

static X509_STORE *x509Store = NULL; /*!< Store contenant les CA, ROOT et CRL pour verif des CERT */

/**
 * \fn int checkCrlIssuer(X509_CRL *xCrl, X509 *xca)
 * \brief chargement d'une CRL ou d'un certificat pour verif la signature de la CRL
 * \param xCrl {pointeur sur CRL}
 * \param xca {pointeur sur Certificat}
 * \return 1 = OK; 0 = KO; -1 = ERROR
 */
static int checkCrlIssuer(X509_CRL *xCrl, X509 *xca)
{
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    pkey = X509_get_pubkey(xca);

    if (!pkey) {
        printf("pb pkey ctx %s %s %d\n",__FILE__, __FUNCTION__, __LINE__);
        return -1;
    }
    ret = X509_CRL_verify(xCrl, pkey);
    EVP_PKEY_free(pkey);

    return ret;
}

/**
 * \fn int checkCrl(const char *crl, int crlSize, int crlType,const char *ca, int caSize, int caType)
 * \brief chargement d'une CRL ou d'un certificat pour verif la signature de la CRL
 * \param crl buffer
 * \param crlSize taille du buffer
 * \param crlType PEM ou DER
 * \param ca buffer
 * \param caSize taille du buffer
 * \param caType PEM ou DER
 * \return 1 = OK; 0 = KO; -1 = ERROR
 */
int checkCrl(const char *crl, int crlSize, int crlType,const char *ca, int caSize, int caType)
{
    X509 *xca = NULL;
    X509_CRL *xCrl = NULL;
    int ret = 0;

    xca = buffTox509Cert(ca, caSize, caType);
    if (xca == NULL)
    {
        printf("*** pb chargement Ca ***\n");
        ret = -1;
        goto end;
    }

    xCrl = buffTox509Crl(crl, crlSize, crlType);
    if (xCrl == NULL)
    {
        printf("*** pb chargement Crl ***\n");
        ret = -1;
        goto end;
    }

    ret = checkCrlIssuer(xCrl, xca);

    end:
    
    X509_CRL_free(xCrl);
    X509_free(xca);

    return ret;
}

/**
 * \fn void initStore()
 * \brief creation du  X509_STORE
 * 
 * cette fontion est appelée automatiquement par loadca et loadcert
 */
void initStore()
{
    if (x509Store == NULL)
    {
#if OPENSSL_API_COMPAT < 0x10100000L
        OpenSSL_add_all_algorithms();
#endif
        x509Store = X509_STORE_new();
    }
}

/**
 * \fn void loadCa(const char *ca,int size, int type)
 * \brief chargement d'un CA ou d'un root pour verification
 * \param ca buffer
 * \param size taille du buffer
 * \param type PEM ou DER
 */
void loadCa(const char *ca, int size, int type)
{
    // TODO verif si autosigner ou check

    X509 *x = NULL;

    initStore();

    x = buffTox509Cert(ca, size, type);
    if (x == NULL)
    {
        printf("*** pb chargement Ca ***\n");
    }
    X509_STORE_add_cert(x509Store, x);
    X509_free(x);
}

/**
 * \fn void loadCrl(const char *crl, int size, int type)
 * \brief chargement d'une Crl pour verification
 * \param crl buffer
 * \param size taille du buffer
 * \param type PEM ou DER
 */
void loadCrl(const char *crl, int size, int type)
{
    X509_CRL *xCrl = NULL;

    initStore();

    xCrl = buffTox509Crl(crl, size, type);
    if (xCrl == NULL)
    {
        printf("*** pb chargement Crl ***\n");
    }

    // TODO verif crl issuer

    if(!X509_STORE_add_crl(x509Store, xCrl)){
        printf("*** add crl KO ***\n");
    };
    
    X509_CRL_free(xCrl);
}

/**
 * \fn void freeStore()
 * \brief chargement d'une Crl pour verification
 * 
 * permet la liberation manuel du X509_STORE
 * si devenu inutile
 *
 */
void freeStore()
{
    if (x509Store != NULL)
        X509_STORE_free(x509Store);
}

/**
 * \fn int checkCert(const char *cert, int size, int type)
 * \brief verifivation d'un certicat
 * 
 * affichage et verification d'un certificat
 * 
 * \param cert buffer
 * \param size taille du buffer
 * \param type PEM ou DER
 * \return 1 = OK; 0 = KO; -1 = ERROR
 */
int checkCert(const char *cert, int size, int type)
{
    X509 *x = NULL;

    if (x509Store == NULL)
    {
        return -1;
    }

    x = buffTox509Cert(cert, size, type);
    if (x == NULL)
    {
        printf("*** pb chargement Cert\n ***");
        return -1;
    }

    printCert(x);

    return check(x);
}

/**
 * \fn static X509* buffTox509Cert(const char *certBuf, int size, int type)
 * \brief convertie un buffer en structure certificat X509
 * 
 * \param certBuff {buffer contenant le certificat en der ou pem}
 * \param size {taille du buffer}
 * \param type {PEM ou DER}
 * \return pointeur sur certificat X509 doit etre free apres utilisation
 */
static X509 *buffTox509Cert(const char *certBuf, int size, int type)
{
    X509 *x = NULL;
    BIO *cert;

    if ((cert = BIO_new(BIO_s_mem())) == NULL)
        goto end;

    BIO_write(cert, certBuf, size);

    if (type == PEM)
    {
        x = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
    }
    else if (type == DER)
    {
        x = d2i_X509_bio(cert, NULL);
    }
    else
    {
        printf("*** ni PEM ni DER ***");
    }

end:
    if (cert != NULL)
        BIO_free(cert);
    return (x);
}

/**
 * \fn static X509_CRL *buffTox509Crl(const char *crlBuf, int size, int type)
 * \brief convertie un buffer en structure crl X509
 * 
 * \param certBuff {buffer contenant le certificat en der ou pem}
 * \param size {taille du buffer}
 * \param type {PEM ou DER}
 * \return pointeur sur crl X509 doit etre free apres utilisation
 */
static X509_CRL *buffTox509Crl(const char *crlBuf, int size, int type)
{
    X509_CRL *x = NULL;
    BIO *bio;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        goto end;

    BIO_write(bio, crlBuf, size);

    if (type == PEM)
    {
        x = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    }
    else if (type == DER)
    {
        x = d2i_X509_CRL_bio(bio, NULL);
    }
    else
    {
        printf("*** ni PEM ni DER ***");
    }

end:
    if (bio != NULL)
        BIO_free(bio);
    return (x);
}

/**
 * \fn static int check(X509 *x)
 * \brief verifie un certificat X509
 * 
 * \param x {certificat a verif}
 * \return 1 = OK; 0 = KO; -1 = ERROR
 */
static int check(X509 *x)
{
    int i = 0, ret = 0;
    unsigned long flags = 0;
    X509_STORE_CTX *ctx;

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL)
        goto end;

    if (!X509_STORE_CTX_init(ctx, x509Store, x, 0))
        goto end;

    // voir flag https://www.openssl.org/docs/man1.1.1/man3/X509_VERIFY_PARAM_set_depth.html
    //flags = (X509_V_FLAG_PARTIAL_CHAIN);
    flags = 0;

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_flags(param, flags);
#else
    X509_STORE_CTX_set_flags(ctx, flags);
#endif    

    i = X509_verify_cert(ctx);

    // TODO: metre dans une callback
    printf("CTX ERROR %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

    X509_STORE_CTX_free(ctx);

    ret = 0;
end:
    ret = (i > 0);

    X509_free(x);

    return (ret);
}

/**
 * \fn static char *asn1_time_to_buff(const ASN1_TIME *time)
 * \brief creer un string dans un buffer a partir d'un ASN1_TIME *
 * 
 * \param time {pointeur sur ASN1_TIME}
 * \return buffer doit etre free
 */
static char *asn1_time_to_buff(const ASN1_TIME *time)
{
    int size = 25;
    BIO *timeBio;
    timeBio = BIO_new(BIO_s_mem());
    char *buff = malloc(size);
    ASN1_TIME_print(timeBio, time);
    BIO_read(timeBio, buff, size);
    BIO_free(timeBio);
    buff[size] = '\0';
    return buff;
}

/**
 * \fn static char *asn1_time_to_buff(const ASN1_TIME *time)
 * \brief creer un string dans un buffer contenant les usages d'un cert
 * 
 * \param cert {pointeur sur certficat}
 * \return buffer doit etre free
 */
static char *usages(X509 *cert)
{
    int size = 256;
    char *buff = malloc(size);
    buff[0] = '\0';
    uint32_t key_usage = X509_get_key_usage(cert);

    if (key_usage & KU_DIGITAL_SIGNATURE)
        strcat(buff, "digitalSignature,");
    if (key_usage & KU_NON_REPUDIATION)
        strcat(buff, "nonRepudiation,");
    if (key_usage & KU_KEY_ENCIPHERMENT)
        strcat(buff, "keyEncipherment,");
    if (key_usage & KU_DATA_ENCIPHERMENT)
        strcat(buff, "dataEncipherment,");
    if (key_usage & KU_KEY_AGREEMENT)
        strcat(buff, "keyAgreement,");
    if (key_usage & KU_KEY_CERT_SIGN)
        strcat(buff, "keyCertSign,");
    if (key_usage & KU_CRL_SIGN)
        strcat(buff, "cRLSign,");
    if (key_usage & KU_ENCIPHER_ONLY)
        strcat(buff, "encipherOnly,");
    if (key_usage & KU_DECIPHER_ONLY)
        strcat(buff, "decipherOnly,");

    buff[strlen(buff) - 1] = '\0';

    return buff;
}

/**
 * \fn static void printCert(X509 *cert)
 * \brief affiche les info d'un certificat
 * 
 * \param cert {pointeur sur certficat}
 */
static void printCert(X509 *cert)
{
    printf("----------------------------------------------------------\n");

    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 2048);
    printf("subject:\n");
    printf(subject);
    printf("\n");
    free(subject);

    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 2048);
    printf("issuer:\n");
    printf(issuer);
    printf("\n");
    free(issuer);

    ASN1_INTEGER *asn1Sn = X509_get_serialNumber(cert);
    char *serialNumber;
    if (asn1Sn->length <= (int)sizeof(long))
    {
        serialNumber = i2s_ASN1_INTEGER(NULL, asn1Sn);
    }
    else
    {
        serialNumber = i2s_ASN1_OCTET_STRING(NULL, asn1Sn);
    }
    printf("serial:\n%s\n", serialNumber);
    free(serialNumber);

    // MEF ne fontionne pas avec length > sizeof(long)
    // long intSerial = ASN1_INTEGER_get(asn1Sn);
    // int64_t sn64;
    // ASN1_INTEGER_get_int64(&sn64, asn1Sn);

    char *noteBefore = asn1_time_to_buff(X509_get0_notBefore(cert));
    char *noteAfter = asn1_time_to_buff(X509_get0_notAfter(cert));
    printf("notBefore:\n");
    printf(noteBefore);
    printf("\n");
    printf("notAfter:\n");
    printf(noteAfter);
    printf("\n");
    free(noteBefore);
    free(noteAfter);

    char *keyUsage = usages(cert);
    printf("keyUsage:\n");
    printf(keyUsage);
    printf("\n");
    free(keyUsage);
}
