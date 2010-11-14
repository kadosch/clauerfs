
/*

                        LICENCIA

1. Este programa puede ser ejecutado sin ninguna restricción
   por parte del usuario final del mismo.

2. La  Universitat Jaume I autoriza la copia y  distribución
   del programa con cualquier fin y por cualquier medio  con
   la  única limitación de que, de forma  apropiada, se haga
   constar  en  cada  una  de las copias la  autoría de esta  
   Universidad  y  una reproducción  exacta de las presentes 
   condiciones   y   de   la   declaración  de  exención  de 
   responsabilidad.

3. La  Universitat  Jaume  I autoriza  la  modificación  del
   software  y  su  redistribución  siempre que en el cambio
   del  código  conste la autoría de la Universidad respecto  
   al  software  original  y  la  url de descarga del código
   fuente  original. Además, su denominación no debe inducir 
   a  error  o  confusión con el original. Cualquier persona
   o  entidad  que  modifique  y  redistribuya  el  software 
   modificado deberá  informar de tal circunstancia mediante
   el  envío  de  un  mensaje  de  correo  electrónico  a la 
   dirección  clauer@uji.es  y  remitir una copia del código 
   fuente modificado.

4. El  código  fuente  de todos los programas amparados bajo 
   esta licencia  está  disponible para su descarga gratuita
   desde la página web http//:clauer.uji.es.

5. El hecho en sí del uso, copia o distribución del presente 
   programa implica la aceptación de estas condiciones.

6. La  copia y distribución del programa supone la extensión 
   de las presentes condiciones al destinatario.
   El  distribuidor no puede imponer condiciones adicionales
   que limiten las aquí establecidas.

       DECLARACIÓN DE EXENCIÓN DE RESPONSABILIDAD

Este  programa  se  distribuye  gratuitamente. La Universitat 
Jaume  I  no  ofrece  ningún  tipo de garantía sobre el mismo
ni acepta ninguna responsabilidad por su uso o  imposibilidad
de uso.

*/

#ifndef __CRYPTOWRAPPER_H__
#define __CRYPTOWRAPPER_H__

#ifdef WIN32
#include <windows.h>
#elif defined(LINUX)
#include <pthread.h>
#endif

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TAM_BLOQUE	10240 /* bytes */

#define CRYPTO_DESCIFRAR		0
#define CRYPTO_CIFRAR			1

#define ALGID_SHA1	0
#define ALGID_MD5	1

#define TAM_SHA1	20 /* bytes */
#define TAM_MD5		16 /* bytes */

/*
 * Algoritmos de cifrado disponibles. Es importante que los números
 * asignados sean consecutivos.
 */

#define CRYPTO_CIPHER_AES_128_CBC   0
#define CRYPTO_CIPHER_AES_192_CBC   1
#define CRYPTO_CIPHER_AES_256_CBC   2

#define CRYPTO_CIPHER_DES_EDE3_CBC  3

/*
 * Tipos de datos
 */




typedef struct CRYPTO_KEY {
    unsigned char *llavePrivada;
    int tamLlavePrivada;   /* en bytes */
} CRYPTO_KEY;


typedef struct DN {
	char *C;
	char *ST;
	char *L;
	char *O;
	char *OU;
	char *CN;
	char *email;
} DN;


#if defined(LINUX)

typedef unsigned int ALG_ID;

typedef struct {
	unsigned int magic;
	unsigned int bitlen;
	unsigned int pubexp;
} RSAPUBKEY;

typedef struct {
	unsigned char bType;
	unsigned char bVersion;
	short reserved;
	ALG_ID aiKeyAlg;
} BLOBHEADER;

#define PRIVATEKEYBLOB 0x7
#define DWORD unsigned int

#endif


/*
 * Prototipos
 */

int CRYPTO_Ini (void);
int CRYPTO_Fin (void);
    
int CRYPTO_KEY_New  ( int algoritmo,  CRYPTO_KEY *cryptoKey);
int CRYPTO_KEY_Free ( CRYPTO_KEY *cryptoKey);
int CRYPTO_Key_Set  ( CRYPTO_KEY *cryptoKey,  unsigned char *llavePrivada,  int tamLlavePrivada);

/* Simetric cipher functions */

int CRYPTO_Descifrar ( CRYPTO_KEY *cryptoKey,  
		       int padding,  
		       int algoritmo,  
		       unsigned char *bufferCifrado,  
		       int tamBufferCifrado,  
		       unsigned char *bufferDescifrado,  
		       int *tamBufferDescifrado);

int CRYPTO_Cifrar ( CRYPTO_KEY *cryptoKey,
		    int padding,  
		    int algoritmo,  
		    unsigned char *buffer,  
		    int tamBuffer,  
		    unsigned char *bufferCifrado,  
		    int *tamBufferCifrado);

/* PBE functions */

int CRYPTO_PBE_Descifrar ( char * password,  
			   unsigned char *salt,
                           unsigned long saltLen,
                           unsigned long iterCount,
			   int padding,  
			   int algoritmo,  
			   unsigned char *bloqueCifrado,  
			   int tamBloqueCifrado,  
			   unsigned char *bloqueDescifrado,  
			   int *tamBloqueDescifrado);

int CRYPTO_PBE_Cifrar ( char * password,  
			unsigned char *salt,
                        unsigned long saltLen,
                        unsigned long iterCount,
			int padding,  
			int algoritmo,  
			unsigned char *bloqueClaro,  
			int tamBloqueClaro, 
			unsigned char *bloqueCifrado, 
			int *tamBloqueCifrado);

/* Message digest functions */

int CRYPTO_Hash    ( int algID,  unsigned char *data,  int dataLen,  unsigned char *hash);

int CRYPTO_Sign	   ( int algID,  
		     unsigned char *data,  
		     unsigned int dataLen, 
		     unsigned char *llavePrivada, 
		     unsigned int tamLlavePrivada, 
		     char * password, 
		     unsigned char *signedData, 
		     unsigned int *signedDataLen );

int CRYPTO_Verify ( int algID,  
		    unsigned char *data, 
		    unsigned int dataLen, 
		    unsigned char *signedData, 
		    unsigned int signedDataLen, 
		    unsigned char *llavePublica, 
		    unsigned int tamLlavePublica );

/* Miscellaneous functions */

int CRYPTO_Random ( int bytes,  
		    unsigned char *bufferRandom );

int CRYPTO_GenerarParLlaves ( char * password, 
			      int bits,  
			      unsigned char **llavePublica, 
			      long *tamLlavePublica,  
			      unsigned char **llavePrivada,  
			      long *tamLlavePrivada);

/* PKCS12 functions */

int CRYPTO_PKCS12_VerificarPassword ( unsigned char *pkcs12,  unsigned long tamPkcs12,  char * pwd);

int CRYPTO_PKCS12_CambiarPassword   ( unsigned char *p12Original,  unsigned long tamP12,  char * pwdOriginal, char * pwdNueva);

int CRYPTO_ParsePKCS12 ( unsigned char *pkcs12,  unsigned long tamPkcs12,  char * pwd,
		         unsigned char *llavePrivada,  unsigned long *tamLlavePrivada,
			 unsigned char *certLlave,  unsigned long *tamCertLlave,
			 unsigned char *certs,  unsigned long *tamCerts, unsigned long *numCerts,
			 char *friendlyNameCert,  unsigned long *tamFriendlyNameCert);

int CRYPTO_PKCS12_Crear	( unsigned char *llavePrivada, unsigned long tamPrivada, char * pwdLlavePrivada,
			  unsigned char *certAsociado, unsigned long tamCert,
			  unsigned char *certsRaiz, unsigned long *tamCertsRaiz, int numRaiz,
			  char * pwd,
			  char *friendlyName,
			  unsigned char *pkcs12,
			  unsigned long *tamPKCS12);

/* Certificate functions 
 */

int CRYPTO_CERT_PEM_Id	       ( unsigned char *certPEM, unsigned long tam, unsigned char id[20] );
int CRYPTO_CERT_Cmp	           ( unsigned char *cert_a,  unsigned long tamCertA,  unsigned char *cert_b,  unsigned long tamCertB );
int CRYPTO_CERT_SubjectIssuer  ( unsigned char *cert, unsigned long tamCert, DN *subject, DN *issuer );
int CRYPTO_X509_EsRoot	       ( unsigned char *cert, unsigned long tamCert );
int CRYPTO_X509_Get_KeyUsage   ( unsigned char *cert, unsigned long tamCert, unsigned long *ex_kusage );
int CRYPTO_X509_DER2PEM        ( unsigned char *derCert, unsigned long tamDER, unsigned char *pemCert, unsigned long *tamPEM);
int CRYPTO_X509_PEM2DER        ( unsigned char *pemCert, unsigned long tamPEM, unsigned char *derCert, unsigned long *tamDER);
int CRYPTO_X509_FingerPrint    ( unsigned char *certPEM, unsigned long tam, int mdAlg, unsigned char *fingerPrint );
int CRYPTO_X509_LLAVE          ( unsigned char *cert, unsigned long tamCert, unsigned char *llavePrivada, unsigned long tamLlavePrivada, char *pwd);

/* Distinguished name functions
 */

DN *CRYPTO_DN_New (void);
int CRYPTO_DN_Free(DN *dn);
int CRYPTO_DN_Limpiar(DN *dn);
int CRYPTO_DN_Igual (DN *dn1, DN*dn2);

/* Utility functions
 */

char * PASSWORD_Nueva    (char *password);
void   PASSWORD_Destruir (char * *password);

#ifdef WIN32
#define CRYPTO_SecureZeroMemory(b,s)  SecureZeroMemory(b,s)
#else
void   CRYPTO_SecureZeroMemory ( void *buf, unsigned long size );
#endif

void   CRYPTO_ByteOrder        ( unsigned char *in, int tamIn );
int    CRYPTO_LLAVE_PEM_Id     ( unsigned char *llavePEM, unsigned long tam, int privada, char * pwd, unsigned char id[20] );

void OSSL_LockingCallback (int mode, int type, const char *file, int line);
int  OSSL_PasswordCallback (char *buf, int size, int rwflag, void *userdata);


int CRYPTO_LLAVE2BLOB (unsigned char *llavePrivada, unsigned long tamLlavePrivada,
			char * pwd, unsigned long alg, 
			unsigned char *blob, unsigned long *tamBlob);

int CRYPTO_BLOB2LLAVE ( unsigned char *blob, unsigned long tamBlob,
	                    unsigned char *llave, unsigned long *tamLlave );


#ifndef WIN32
unsigned long OSSL_ThreadId (void);
#endif

/* Los key Usage. Un mapeado de nombres directamente del OpenSSL
 */

#define CRYPTO_KU_DIGITAL_SIGNATURE    0x0080
#define CRYPTO_KU_NON_REPUDIATION      0x0040
#define CRYPTO_KU_KEY_ENCIPHERMENT     0x0020
#define CRYPTO_KU_DATA_ENCIPHERMENT    0x0010
#define CRYPTO_KU_KEY_AGREEMENT        0x0008
#define CRYPTO_KU_KEY_CERT_SIGN        0x0004
#define CRYPTO_KU_CRL_SIGN             0x0002
#define CRYPTO_KU_ENCIPHER_ONLY        0x0001
#define CRYPTO_KU_DECIPHER_ONLY        0x8000

/* Los extended key usage
 */

#define CRYPTO_XKU_SSL_SERVER          0x1
#define CRYPTO_XKU_SSL_CLIENT          0x2
#define CRYPTO_XKU_SMIME               0x4
#define CRYPTO_XKU_CODE_SIGN           0x8
#define CRYPTO_XKU_SGC                 0x10
#define CRYPTO_XKU_OCSP_SIGN           0x20
#define CRYPTO_XKU_TIMESTAMP           0x40
#define CRYPTO_XKU_DVCS                0x80

/************************************************************************************/
/* Códigos de error
 */

#define ERR_CW_NO                               0
#define ERR_CW_SI                               1
#define ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE       2
#define ERR_CW_FIRMA_CORRECTA                   3
#define ERR_CW_OUT_OF_MEMORY			4
#define ERR_CW_INVALID_PARAMETER                5

#ifdef __cplusplus
}
#endif

#endif


