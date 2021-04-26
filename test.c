#include <stdio.h>
#include <stdlib.h>

#include "certChecker.h"

int charger(char * file, char ** buff);

int main()
{
    char * monCert;
    int monCertLen;
    char * monRoot;
    int monRootLen;
    char * monCa;
    int monCaLen;
    char * crl;
    int crlLen;

    int ret;

    monCertLen = charger("certDir/endUser.pem",&monCert);
    monRootLen = charger("certDir/root.pem",&monRoot);
    monCaLen = charger("certDir/ca.pem",&monCa);
    crlLen = charger("certDir/cacrl.pem",&crl);

    if(checkCrl(crl,crlLen,PEM,monCa,monCaLen,PEM) > 0)
        printf("crl ok");

    loadCa(monCa,monCaLen,PEM);
    loadCrl(crl,crlLen,PEM);

    ret = checkCert(monCert,monCertLen,PEM);
    printf("false %d\n",ret);

    ret = checkCert(monRoot,monRootLen,PEM);
    printf("true %d\n",ret);

    loadCa(monRoot,monRootLen,PEM);

    ret = checkCert(monCert,monCertLen,PEM);
    printf("true %d\n",ret);

    freeStore();
}

/**
 * \fn int charger(char * file, char ** buff)
 * \brief chargement d'un fichier dans un buffer
 * \return taille du fichier
 */
int charger(char * file, char ** buff)
{
    FILE* fd = fopen(file,"r");
    if(!fd){
        printf("error fd\n");
        return -1;
    }
    // may be replace by fstat() and stat.st_size
    fseek(fd,0,SEEK_END);
    int size = ftell(fd);
    fseek(fd,0,SEEK_SET);
    *buff = malloc(size+1);
    fread(*buff,1,size,fd);
    fclose(fd);
    return size;
}