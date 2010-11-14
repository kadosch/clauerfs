
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

#include "CRYPTOWrap.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>

#ifdef WIN32
#include <wincrypt.h>
#endif

#ifdef WIN32
/*! \brief Mutex para la getión de concurrencia en OpenSSL. */
static HANDLE *mutex;
#else
static pthread_mutex_t *mutex;
static long *lock_count;
#endif

/*! \brief Indica si la librería ya ha sido inicializada. */
static int OpenSSLInit = 0;


EVP_CIPHER **tablaAlgoritmos = NULL;


/*! \brief Inicializa la librería.
 *
 * Inicializa la librería. Antes de usarla es necesario llamar a esta función.
 *
 * \retval ERR_CW_NO
 *		   La función terminó correctamente.
 * 
 * \retval !ERR_CW_NO
 *		   Ocurrió algún error en la función.
 */

int CRYPTO_Ini (void)
{
  int i;

  if ( OpenSSLInit ) 
    return ERR_CW_NO;

  mutex = NULL;

  OpenSSL_add_all_algorithms();

  /* Cargo la tabla de algoritmos
   */

  tablaAlgoritmos = (EVP_CIPHER **) malloc (sizeof(EVP_CIPHER *) * 4);

  if ( ! tablaAlgoritmos )
    return ERR_CW_OUT_OF_MEMORY;

  tablaAlgoritmos[CRYPTO_CIPHER_AES_128_CBC] = (EVP_CIPHER *) EVP_aes_128_cbc();
  tablaAlgoritmos[CRYPTO_CIPHER_AES_192_CBC] = (EVP_CIPHER *) EVP_aes_192_cbc();
  tablaAlgoritmos[CRYPTO_CIPHER_AES_256_CBC] = (EVP_CIPHER *) EVP_aes_256_cbc();
  tablaAlgoritmos[CRYPTO_CIPHER_DES_EDE3_CBC] = (EVP_CIPHER *) EVP_des_ede3_cbc();

  /* Gestión de threads
   */

#ifdef WIN32
  mutex = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));

  if ( !mutex ) 
    return !ERR_CW_NO;
  
  
  for ( i = 0 ; i < CRYPTO_num_locks() ; i++ )
    mutex[i] = CreateMutex(NULL,0,NULL);
  
  
  CRYPTO_set_locking_callback(OSSL_LockingCallback);
#else
  mutex      = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
 
  if ( ! mutex )
    return ERR_CW_OUT_OF_MEMORY;


  lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

  if ( ! lock_count )
    return ERR_CW_OUT_OF_MEMORY;
  
  for (i=0 ; i < CRYPTO_num_locks() ; i++ ) {
    lock_count[i] = 0;
    pthread_mutex_init(&(mutex[i]), NULL);
  }
  
  CRYPTO_set_id_callback((unsigned long (*)())OSSL_ThreadId);
  CRYPTO_set_locking_callback((void (*)())OSSL_LockingCallback);
#endif

  OpenSSLInit = 1;

  return ERR_CW_NO;
}


/*!
 * \brief Libera los recursos ocupados por la librería.
 *
 * Libera los recursos ocupados por la librería. Esta función se llama cuando ya no vamos
 * a utilizar más la librería.
 */

int CRYPTO_Fin (void)
{
  int i;

  if (!OpenSSLInit)
    return ERR_CW_NO;

  free(tablaAlgoritmos);

  CRYPTO_set_locking_callback(NULL);

#ifdef WIN32
  for ( i = 0 ; i< CRYPTO_num_locks() ; i++ )
    CloseHandle(mutex[i]);
#else
  for (i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(mutex[i]));

  OPENSSL_free(lock_count);
#endif

  OPENSSL_free(mutex);
  mutex = NULL;

  /*ERR_free_strings();*/

  EVP_cleanup();

  OpenSSLInit = 0;

  return ERR_CW_NO;

}

/*! \brief Descifrado basado en password de un buffer.
 *
 * Descifrado basado en password de un buffer utilizando el esquema de
 * cifrado PBES2 de PKCS#5.
 *
 * \param password
 *        La password que "se utilizará" para descifrar el bloque.
 *
 * \param salt
 *        El salt que se utilizará para la derivación de la llave.
 *
 * \param saltLen
 *        El tamaño de salt en bytes
 *
 * \param iterCount
 *        El iteration count
 *
 * \param padding
 *        Indica si se realizó o no padding pkcs#5 en el buffer cifrado.
 *
 * \param algoritmo
 *        El algoritmo de descifrado a emplear
 *
 * \param bloqueCifrado
 *        El buffer a descifrar
 *
 * \param tamBloqueCifrado
 *        El tamaño, en bytes, del buffer a cifrar
 *
 * \param bloqueDescifrado
 *        El buffer descifrado
 *
 * \param tamBloqueDescifrado
 *        El tamaño del buffer descifrado en bytes.
 *
 * \retval ERR_CW_NO
 *         La función se ejecutó sin errores.
 *
 * \retval !ERR_CW_NO
 *         La función tiene un error.
 */

int CRYPTO_PBE_Descifrar ( char * password,  
                           unsigned char *salt,  unsigned long saltLen, unsigned long iterCount, 
                           int padding,  
                           int algoritmo,
                           unsigned char *bloqueCifrado,  int tamBloqueCifrado,
                           unsigned char *bloqueDescifrado,  int *tamBloqueDescifrado )
{

  X509_ALGOR *alg = NULL;
  EVP_CIPHER_CTX ctx;
  unsigned char *iv;
  int tamSalida, auxTam;
  EVP_CIPHER *cipher = NULL;

  cipher = tablaAlgoritmos[algoritmo];

  /*
   * Si bloqueDescifrado es NULL entonces devolvemos el tamaño máximo
   * posible que puede ocupar el buffer descifrado.
   */
  
  if ( !bloqueDescifrado) {
    *tamBloqueDescifrado = tamBloqueCifrado + EVP_CIPHER_block_size(cipher);
    return ERR_CW_NO;
  }

  /*
   * Vector de inicialización a piño fijo
   */

  iv = (unsigned char *) OPENSSL_malloc (EVP_CIPHER_iv_length(cipher));

  if ( ! iv )
    return ERR_CW_OUT_OF_MEMORY;

  memset(iv, 0, EVP_CIPHER_iv_length(cipher));

  alg = PKCS5_pbe2_set(cipher, iterCount, salt, saltLen);

  if ( !alg ) {
    OPENSSL_free(iv);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  EVP_CIPHER_CTX_init(&ctx);
  
  if ( !EVP_PBE_CipherInit(alg->algorithm, password, strlen(password), alg->parameter, &ctx, CRYPTO_DESCIFRAR) ) {
    OPENSSL_free(iv);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  EVP_CIPHER_CTX_set_padding(&ctx, padding);
  
  if ( !EVP_CipherInit_ex(&ctx, NULL, NULL, NULL, iv, CRYPTO_DESCIFRAR) ) {
    OPENSSL_free(iv);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }
  
  if ( !EVP_CipherUpdate(&ctx, bloqueDescifrado, &auxTam, bloqueCifrado, tamBloqueCifrado) ) {
    OPENSSL_free(iv);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }
  
  if ( ! EVP_CipherFinal_ex(&ctx, bloqueDescifrado + auxTam, &tamSalida) ) {
    OPENSSL_free(iv);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }


  (*tamBloqueDescifrado) = auxTam + tamSalida;
  
  EVP_CIPHER_CTX_cleanup(&ctx);

  OPENSSL_free(iv);
  iv = NULL;

  return ERR_CW_NO;

}

/*! \brief Cifrado basado en password de un buffer.
 *
 * Cifrado basado en password de un buffer utilizando el esquema de
 * cifrado PBES2 de PKCS#5.
 *
 * \param password
 *	  La password que "se utilizará" para cifrar el bloque.
 *
 * \param salt
 *        El salt que se utilizará para la derivación de la llave.
 *
 * \param saltLen
 *        El tamaño de salt en bytes
 *
 * \param iterCount
 *        El iteration count
 *
 * \param padding
 *        Indica si realizar o no padding pkcs#5 en el buffer cifrado.
 *
 * \param algoritmo
 *        El algoritmo de cifrado a emplear
 *
 * \param bloqueClaro
 *	  El buffer a cifrar
 *
 * \param tamBloqueClaro
 *        El tamaño, en bytes, del buffer a cifrar
 *
 * \param bloqueCifrado
 *	  El buffer cifrado.
 *
 * \param tamBloqueCifrado
 *        El tamaño del buffer cifrado en bytes.
 *
 * \retval ERR_CW_NO
 *	   La función se ejecutó sin errores.
 *
 * \retval !ERR_CW_NO
 *	   La función tiene un error.
 */

int CRYPTO_PBE_Cifrar ( char * password,
                        unsigned char *salt, unsigned long saltLen, unsigned long iterCount,
                        int padding,  
                        int algoritmo,
                        unsigned char *bloqueClaro, int tamBloqueClaro,
                        unsigned char *bloqueCifrado,  int *tamBloqueCifrado )
{
  X509_ALGOR *alg = NULL;
  EVP_CIPHER_CTX ctx;
  int tamSalida, auxTam;

  unsigned char *iv = NULL;
  EVP_CIPHER *cipher = NULL;

  int ret = ERR_CW_NO;


  if ( !bloqueCifrado ) {
    *tamBloqueCifrado = tamBloqueClaro + EVP_CIPHER_block_size(cipher);
    ret = ERR_CW_NO;
    goto finCRYPTO_PBE_Cifrar;
  }

  cipher = tablaAlgoritmos[algoritmo];

  iv = (unsigned char *) OPENSSL_malloc (EVP_CIPHER_iv_length(cipher));

  if ( ! iv )
    return ERR_CW_OUT_OF_MEMORY;

  memset(iv, 0, EVP_CIPHER_iv_length(cipher));

  alg = PKCS5_pbe2_set(cipher, iterCount, salt, saltLen);

  if ( !alg ) {
    ret = ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
    goto finCRYPTO_PBE_Cifrar;
  }

  EVP_CIPHER_CTX_init(&ctx);

  if ( !EVP_PBE_CipherInit(alg->algorithm, password, strlen(password), alg->parameter, &ctx, CRYPTO_CIFRAR) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    ret = ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
    goto finCRYPTO_PBE_Cifrar;
  }

  EVP_CIPHER_CTX_set_padding(&ctx, padding);

  if ( !EVP_CipherInit_ex(&ctx, NULL, NULL, NULL, iv, CRYPTO_CIFRAR) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    ret = ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
    goto finCRYPTO_PBE_Cifrar;
  }


  if ( !EVP_CipherUpdate(&ctx, bloqueCifrado, &auxTam, bloqueClaro, tamBloqueClaro) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    ret = ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
    goto finCRYPTO_PBE_Cifrar;
  }

  if ( ! EVP_CipherFinal_ex(&ctx, bloqueCifrado + auxTam, &tamSalida) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    ret = ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
    goto finCRYPTO_PBE_Cifrar;
  }

  (*tamBloqueCifrado) = tamSalida + auxTam;

  EVP_CIPHER_CTX_cleanup(&ctx);

finCRYPTO_PBE_Cifrar:

  if ( !alg ) {
    X509_ALGOR_free(alg);
    alg = NULL;
  }

  if ( iv ) {
    OPENSSL_free(iv);
    iv = NULL;
  }

  return ret;
}

/*!
 * \brief Devuelve bytes bytes aleatorios en el buffer Random.
 *
 * Devuelve bytes bytes de información en el buffer Random.
 *
 * \param bytes
 *		  Número de bytes aleatorios a obtener.
 *
 * \param bufferRandom
 *		  Buffer de salida con los datos aleatorios.
 *
 * \retval ERR_CW_NO
 *		   La función se ejecutó con éxito.
 *
 * \retval != ERR_CW_NO
 *		   Se produjo un error en la función.
 */

int CRYPTO_Random ( int bytes,  unsigned char *bufferRandom)
{

  if ( ! RAND_pseudo_bytes(bufferRandom, bytes) )
    return ERR_CW_SI;

  return ERR_CW_NO;

}

/*!
 * \brief Devuelve una nueva char * inicializada al argumento password.
 *
 * Devuelve una nueva char * inicializada al argumento password. Machaca el contenido del
 * argumento con valores aleatorios. Es responsabilidad del programador liberar el espacio
 * reservado para password.
 *
 * \param password
 *		  La password que se utilizará para inicializar el objeto devuelto.
 *
 * \retval NULL
 *		   No se pudo crear la nueva password.
 *
 * \remarks El argumento password queda machacado completamente. Es responsabilidad del
 *			programador liberar el espacio ocupado por ésta.
 */

char * PASSWORD_Nueva(char *password)
{
  char * salida = NULL;
  int tamPassword=33;
  int err = 0;

  salida = (char *) malloc (tamPassword+1);

  if ( !salida ) {
    err = 1;
    goto finPASSWORD_Nueva;
  }

#ifdef WIN32

  /* Esta función en Windows 98/95/Me no tiene ningún efecto. Mantengo la password
   * en memoria principal. ATENCION :: si el usuario no posee el privilegio
   * SeLockMemory... ¿?
   */

  if ( ! VirtualLock (salida, tamPassword+1) ) {
    err = 1;
    goto finPASSWORD_Nueva;
  }

#endif

  memset(salida,0,tamPassword+1);
  strncpy(salida, password,tamPassword);

  /* Machaco el contenido de password de entrada con datos aleatorios */

  CRYPTO_SecureZeroMemory(password, strlen(password)+1);

finPASSWORD_Nueva:

  if ( err ) {
    if ( salida ) {
      CRYPTO_SecureZeroMemory(salida, tamPassword+1);
      salida = NULL;
    }
  }

  return salida;
}

/*!
 * \brief Machaca el contenido de *password y lo libera.
 *
 * Machaca el contenido de *password y lo libera.
 *
 * \param password
 *		  La password que se desea liberar.
 *
 * \remarks Nótese que se pasa un puntero a password.
 */

void PASSWORD_Destruir(char * *password)
{
  int tamPassword = strlen(*password);

  CRYPTO_SecureZeroMemory(*password, tamPassword+1);

#ifdef WIN32
  VirtualUnlock(password, 34);
#endif

  free(*password);
  *password = NULL;

}

/*!
 * \brief Callback para gestionar el acceso a recursos compartidos.
 *
 * Callback para gestionar el acceso a recursos compartidos. Es una función que no
 * debe ser llamada desde fuera. Sólo para la gestión del OpenSSL.
 *
 */

void OSSL_LockingCallback (int mode, int type, const char *file, int line)
{
#ifdef WIN32
  if ( mode & CRYPTO_LOCK )
    WaitForSingleObject(mutex[type], INFINITE);
  else
    ReleaseMutex(mutex[type]);
#endif

}

/*! \brief Genera un par de llaves RSA.
 *
 * Genera un par de llaves RSA y las devuelve en los buffers llavePublica y llavePrivada en
 * formato PEM. La llave privada se cifrada con la password password mediante AES en modo
 * CBC de 256 bits.
 *
 * \param password
 *		  La password que se utiliza para cifrar la llave privada.
 *
 * \param bits
 *		  Tamaño de las llaves en bits.
 *
 * \param llavePublica
 *		  Buffer donde irá a parar la llave pública en formato PEM.
 *
 * \param tamLlavePublica
 *		  Tamaño (bytes) del buffer que almacena la llave pública.
 *
 * \param llavePrivada
 *		  Buffer donde irá a parar la llave privada cifrada en formato PEM.
 *
 * \param tamLlavePrivada
 *		  Tamaño (bytes) del buffer que almacena la llave pública.
 *
 * \retval ERR_CW_SI
 *		   Ocurrió un error indefinido.
 *
 * \retval ERR_CW_NO
 *		   La función se ejecutó correctamente.
 *
 * \remarks Utiliza un exponente público a piño fijo (el 3).
 *
 */

int CRYPTO_GenerarParLlaves ( char * password,  int bits,
    unsigned char **llavePublica,  long *tamLlavePublica,
    unsigned char **llavePrivada,  long *tamLlavePrivada)
{

  RSA *rsaLlave = NULL;
  BIO *bioMem = NULL;

  /*
   * A generar...
   */

  rsaLlave = RSA_generate_key(bits, 3, NULL, NULL);

  if ( !rsaLlave )
    return ERR_CW_SI;

  /*
   * Obtenemos la llave pública y privada en formato PEM
   */

  bioMem = BIO_new(BIO_s_mem());
  BIO_set_close(bioMem, BIO_NOCLOSE);

  if ( !bioMem ) {
    RSA_free(rsaLlave);
    rsaLlave = NULL;
    return ERR_CW_SI;
  }


  if ( !PEM_write_bio_RSAPublicKey(bioMem, rsaLlave) ) {
    BIO_free(bioMem);
    bioMem = NULL;
    RSA_free(rsaLlave);
    rsaLlave = NULL;
    return ERR_CW_SI;
  }

  *tamLlavePublica = BIO_get_mem_data(bioMem, llavePublica);

  BIO_free(bioMem);

  bioMem = BIO_new(BIO_s_mem());
  BIO_set_close(bioMem, BIO_NOCLOSE);

  if ( !bioMem ) {
    RSA_free(rsaLlave);
    rsaLlave = NULL;
    OPENSSL_free(*llavePublica);
    llavePublica = NULL;

    return ERR_CW_SI;
  }

  if ( !PEM_write_bio_RSAPrivateKey(bioMem,rsaLlave,EVP_aes_256_cbc(),(unsigned char *)password,strlen(password),NULL,NULL) ) {
    RSA_free(rsaLlave);
    rsaLlave = NULL;
    OPENSSL_free(*llavePublica);
    llavePublica = NULL;
    BIO_free(bioMem);
    bioMem = NULL;

    return ERR_CW_SI;
  }

  *tamLlavePrivada = BIO_get_mem_data(bioMem, llavePrivada);

  BIO_free(bioMem);
  RSA_free(rsaLlave);
  bioMem = NULL;
  rsaLlave = NULL;

  return ERR_CW_NO;

}

/*! \brief Calcula el resumen de data
 *
 * Calcula el resumen de data. Es posible utilizar bien MD5 bien SHA1.
 *
 * \param algID
 *		  Identifica el algoritmo que queremos emplear para calcular el MD. Puede tomar
 *		  actualmente dos valores: ALGID_SHA1 ó ALGID_MD5.
 *
 * \param data
 *		  Los datos para los que queremos calcular el resumen.
 *
 * \param dataLen
 *		  El tamaño en bytes de los datos de entrada.
 *
 * \param hash
 *		  El resumen de data. Debe contener espacio suficiente para albergar el
 *		  resumen del algoritmo seleccionado. El tamaño de SHA1 se puede obtener mediante
 *		  la macro TAM_SHA1 y el de MD5 mediante TAM_MD5.
 *
 * \retval ERR_CW_SI
 *		   Ocurrió un error.
 *
 * \retval ERR_CW_NO
 *		   La función se ejecutó correctamente.
 *
 * \todo La función no produce errores de ejecución. Sin embargo, no se ha revisado que
 *		 el cálculo de los resúmenes sea el correcto.
 *
 */

int CRYPTO_Hash ( int algID,  unsigned char *data,  int dataLen,  unsigned char *hash)
{
  EVP_MD *md = NULL;
  EVP_MD_CTX *mdCtx;

  switch (algID) {
    case ALGID_SHA1:
      md = (EVP_MD *) EVP_sha1();
      break;

    case ALGID_MD5:
      md = (EVP_MD *) EVP_md5();
      break;

    default:
      return ERR_CW_SI;
  }

  mdCtx = EVP_MD_CTX_create();

  if ( !mdCtx ) 
    return ERR_CW_SI;

  if (!EVP_DigestInit_ex(mdCtx, md, NULL)) {
    EVP_MD_CTX_destroy(mdCtx);
    return ERR_CW_SI;
  }


  if ( !EVP_DigestUpdate(mdCtx,data,dataLen) ) {
    EVP_MD_CTX_destroy(mdCtx);
    return ERR_CW_SI;
  }


  if ( !EVP_DigestFinal_ex(mdCtx, hash, NULL) ) {
    EVP_MD_CTX_destroy(mdCtx);
    return ERR_CW_SI;
  }


  EVP_MD_CTX_destroy(mdCtx);

  return ERR_CW_NO;

}

/*! \brief Calcula la firma de data.
 *
 * Calcula la firma de data utilizando como función resumen el algoritmo indicado en
 * algID. La llave privada se pasa en formato PEM y cifrada.
 *
 * \param algID
 *		  La función resumen empleada en la firma,
 *
 * \param data
 *		  Los datos que queremos firmar.
 *
 * \param dataLen
 *		  El tamaño de data.
 *
 * \param llavePrivada
 *		  La llave privada en formato PEM.
 *
 * \param tamLlavePrivada
 *		  El tamaño de llavePrivada.
 *
 * \param password
 *		  La password para descifrar llavePrivada.
 *
 * \param signedData
 *		  La firma calculada. Debe ser pasado con suficiente espacio reservado.
 *		  Se puede saber como mucho el tamaño que va a ocupar la firma haciendo una
 *		  llamada inicialmente con este parámetro a NULL.
 *
 * \param signedDataLen
 *		  El tamaño de la firma.
 *
 * \retval ERR_CW_NO
 *		   La función se ejecutó correctamente.
 *
 * \retval ERR_CW_SI
 *		   Ocurrió un error indefinido.
 *
 * \todo Comprobar que realmente las firmas que calcula son firmas :)
 */


int CRYPTO_Sign ( int algID, 
		  unsigned char *data,  unsigned int dataLen, 
		  unsigned char *llavePrivada,  unsigned int tamLlavePrivada,
		  char * password,
		  unsigned char *signedData,  unsigned int *signedDataLen)
{
  EVP_MD *md = NULL;
  EVP_MD_CTX *mdCtx;

  EVP_PKEY *evpLlave = NULL;
  BIO *bioMem = NULL;

  switch (algID) {
    case ALGID_SHA1:
      md = (EVP_MD *) EVP_sha1();
      break;

    case ALGID_MD5:
      md = (EVP_MD *) EVP_md5();
      break;

    default:
      return ERR_CW_SI;
  }

  mdCtx = EVP_MD_CTX_create();

  if ( !mdCtx ) 
    return ERR_CW_SI;

  if (!EVP_SignInit_ex(mdCtx, md, NULL)) {
    EVP_MD_CTX_destroy(mdCtx);
    return ERR_CW_SI;
  }

  if ( !EVP_SignUpdate(mdCtx,data,dataLen) ) {
    EVP_MD_CTX_destroy(mdCtx);
    return ERR_CW_SI;
  }

  /*
   * Recuperamos la llave privada
   */

  bioMem = BIO_new_mem_buf(llavePrivada,tamLlavePrivada);

  if ( !bioMem ) {
    EVP_MD_CTX_destroy(mdCtx);
    return ERR_CW_SI;
  }


  evpLlave = PEM_read_bio_PrivateKey(bioMem, NULL, OSSL_PasswordCallback, password);

  if ( !evpLlave ) {
    EVP_MD_CTX_destroy(mdCtx);
    BIO_free(bioMem);
    return ERR_CW_SI;
  }

  if ( !signedData ) {
    BIO_free(bioMem);
    EVP_MD_CTX_destroy(mdCtx);
    *signedDataLen = EVP_PKEY_size(evpLlave);
    return ERR_CW_NO;
  }

  if ( !EVP_SignFinal(mdCtx, signedData, signedDataLen,evpLlave) ) {
    EVP_MD_CTX_destroy(mdCtx);
    EVP_PKEY_free(evpLlave);
    BIO_free(bioMem);

    mdCtx = NULL;
    evpLlave = NULL;
    bioMem = NULL;

    return ERR_CW_SI;
  }

  EVP_PKEY_free(evpLlave);
  evpLlave = NULL;
  EVP_MD_CTX_destroy(mdCtx);
  BIO_free(bioMem);

  bioMem = NULL;

  return ERR_CW_NO;
}

/*! \brief Callback para el paso de password a las funciones de lectura PEM.
 *
 * Callback para el paso de password a las funciones de lectura PEM. Es una función de uso
 * interno que no debe ser llamada desde fuera.
 *
 */

int OSSL_PasswordCallback (char *buf, int size, int rwflag, void *userdata)
{
  char * *pwd = (char * *) userdata;
  int tamPassword;

  tamPassword = strlen((char *)pwd);
  size = ( tamPassword >= size ) ? size : tamPassword;

  strncpy(buf, (char *)pwd, size);

  return (tamPassword > size) ? size : tamPassword;

}

/*! \brief Función para verificar una firma RSA
 *
 * Función para verificar una firma RSA
 *
 * \param algID
 *        El algoritmo resumen empleado en la firma. Puede
 *        ser ALGID_SHA1 o ALGID_MD5
 *
 * \param data
 *        La información a verificar
 *
 * \param dataLen
 *        El tamaño en bytes de data
 *
 * \param signedData
 *        La firma
 *
 * \param signedDataLen
 *        El tamaño, en bytes, de signedData.
 *
 * \param llavePublica
 *        La llave pública en formato PEM
 *
 * \param tamLlavePublica
 *        El tamaño, en bytes, de llavePublica. 
 *
 * \retval ERR_CW_NO
 *         Firma incorrecta
 *
 * \retval ERR_CW_FIRMA_CORRECTA
 *         Firma correcta
 * 
 * \retval ERR_CW_SI
 *         Error
 * 
 */

int CRYPTO_Verify ( int algID,  unsigned char *data,  unsigned int dataLen,
    unsigned char *signedData,  unsigned int signedDataLen,
    unsigned char *llavePublica,  unsigned int tamLlavePublica)
{

  EVP_MD_CTX *mdCtx = NULL;
  EVP_MD *md = NULL;

  EVP_PKEY *evpPublica = NULL;
  RSA *rsaPublica = NULL;
  BIO *bioMem = NULL;

  int salida;

  switch (algID) {
    case ALGID_SHA1:
      md =(EVP_MD *) EVP_sha1();
      break;

    case ALGID_MD5:
      md = (EVP_MD *) EVP_md5();
      break;

    default:
      return ERR_CW_SI;
  }


  /*
   * Obtengo la llave pública
   */

  bioMem = BIO_new_mem_buf(llavePublica, tamLlavePublica);

  if ( !bioMem )
    return ERR_CW_SI;

  rsaPublica = PEM_read_bio_RSAPublicKey(bioMem, NULL, NULL, NULL);
  if ( !rsaPublica )
  {
    BIO_free(bioMem);
    bioMem = NULL;
    return ERR_CW_SI;
  }

  evpPublica = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(evpPublica, rsaPublica);

  BIO_free(bioMem);
  bioMem = NULL;

  mdCtx = EVP_MD_CTX_create();

  if ( ! mdCtx ) {
    EVP_PKEY_free(evpPublica);
    return ERR_CW_SI;
  }

  if ( !EVP_VerifyInit_ex(mdCtx, md, NULL) ) {
    EVP_PKEY_free(evpPublica);
    EVP_MD_CTX_destroy(mdCtx);
    mdCtx = NULL;
    return ERR_CW_SI;
  }

  if ( !EVP_VerifyUpdate(mdCtx, data, dataLen) ) {
    EVP_PKEY_free(evpPublica);
    EVP_MD_CTX_destroy(mdCtx);
    mdCtx = NULL;
    return ERR_CW_SI;
  }

  switch ( EVP_VerifyFinal(mdCtx, signedData, signedDataLen, evpPublica) ) {

    case 1 :
      salida = ERR_CW_NO;
      break;

    case 0:
      salida = ERR_CW_FIRMA_CORRECTA;
      break;

    default:
      salida = ERR_CW_SI;
      break;

  }

  EVP_PKEY_free(evpPublica);

  return salida;

}





/*****************************************************************************************/
/*! \brief Parsea un pkcs12.
 *
 * Parsea un pkcs12. El pkcs12 se pasará íntegramente en un buffer (pkcs12) de tamaño tamPkcs12.
 *
 * \param pkcs12
 *		  Es el buffer que contiene el pkcs12 a parsear.
 *
 * \param tamPkcs12
 *		  El tamaño del buffer que contiene el pkcs12 a parsear.
 *
 * \param pwd
 *		  La password que se utilizó para cifrar el pkcs12. Se utiliza también para cifrar la
 *		  la llave privada.
 *
 * \param llavePrivada
 *		  La llave privada que contiene el pkcs12. Debe ser un buffer con memoria reservada.
 *		  Para saber el tamaño que se debe reservar se puede realizar una llamada a la función
 *		  con llavePrivada a NULL.
 *
 * \param tamLlavePrivada
 *		  El tamaño de la llave privada.
 *
 * \param certLlave
 *	      El certificado correspondiente a la llave privada. Debe ser un buffer con memoria reservada.
 *		  Para saber el tamaño que se debe reservar se puede realizar una llamada a la función
 *		  con certLlave a NULL.
 *
 * \param tamCertLlave
 *		  El tamaño del certificado correspondiente a la llave privada.
 *
 * \param certs
 *		  Vector con los certificados raíz contenidos en el pkcs12. Debe ser un buffer con memoria reservada.
 *		  Para saber el tamaño que se debe reservar se puede realizar una llamada a la función
 *		  con certs a NULL.
 *
 * \param tamCerts
 *		  El tamaño del vector certs.
 *
 * \retval ERR_CW_NO
 *		   La función se ejecutó con éxito.
 *
 * \retval ERR_CW_SI
 *		   Ocurrió un error indefinido.
 *
 */

int CRYPTO_ParsePKCS12 ( unsigned char *pkcs12,  unsigned long tamPkcs12,  char * pwd,
    unsigned char *llavePrivada,  unsigned long *tamLlavePrivada,
    unsigned char *certLlave,  unsigned long *tamCertLlave,
    unsigned char *certs,  unsigned long *tamCerts, unsigned long *numCerts,
    char *friendlyNameCert,  unsigned long *tamFriendlyNameCert)
{
  BIO *bioMem = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *evpLlave = NULL;
  X509 *x509Llave = NULL;
  STACK_OF(X509) *ca = NULL;
  X509 *auxCert = NULL;

  char *friendlyName;

  unsigned long i;

  /*
   * Obtengo el pkcs12 en formato interno
   */

  bioMem = BIO_new_mem_buf(pkcs12, tamPkcs12);

  if ( !bioMem )
    return ERR_CW_SI;

  if ( !d2i_PKCS12_bio(bioMem, &p12) ) {
    BIO_free(bioMem);
    bioMem = NULL;
    return ERR_CW_SI;
  }

  /*
   * Parseamos el monstruo
   */

  if ( !PKCS12_parse(p12, pwd, &evpLlave, &x509Llave, &ca) ) {
    BIO_free(bioMem);
    bioMem = NULL;
    PKCS12_free(p12);
    p12 = NULL;
    return ERR_CW_SI;
  }

  BIO_free(bioMem);
  bioMem = NULL;
  PKCS12_free(p12);
  p12 = NULL;


  if ( tamFriendlyNameCert ) { 

    *tamFriendlyNameCert = 0;
    friendlyName = (char * )X509_alias_get0(x509Llave, (int *) tamFriendlyNameCert);

    if ( friendlyName && friendlyNameCert ) 
      strcpy(friendlyNameCert, friendlyName);	
  }

  /*
   * Obtenemos la llave Privada
   */

  bioMem = BIO_new(BIO_s_mem());
  if ( !bioMem ) 
    return ERR_CW_SI;


  if ( tamLlavePrivada ) {
    if ( !PEM_write_bio_PrivateKey(bioMem, evpLlave, NULL,NULL,-1,NULL,NULL) ) {
      BIO_free(bioMem);
      bioMem = NULL;
      return ERR_CW_SI;
    }

    if ( llavePrivada ) {
      unsigned char *aux = NULL;
      *tamLlavePrivada = BIO_get_mem_data(bioMem, &aux);
      memcpy(llavePrivada,aux,*tamLlavePrivada);
      CRYPTO_Random(*tamLlavePrivada,aux);
      CRYPTO_Random(*tamLlavePrivada,aux);
    } else
      *tamLlavePrivada = BIO_get_mem_data(bioMem, NULL);


    BIO_free(bioMem);
    bioMem = NULL;
    EVP_PKEY_free(evpLlave);
  }

  /*
   * Obtenemos el certificado correspondiente a la llave privada
   */

  if ( tamCertLlave ) {

    bioMem = BIO_new(BIO_s_mem());
    BIO_set_close(bioMem, BIO_NOCLOSE);

    if ( !PEM_write_bio_X509(bioMem, x509Llave) ) {
      if ( tamLlavePrivada && llavePrivada ) {
	CRYPTO_Random(*tamLlavePrivada, llavePrivada);
	CRYPTO_Random(*tamLlavePrivada, llavePrivada);
      }
      BIO_free(bioMem);
      bioMem = NULL;
      return ERR_CW_SI;
    }

    if ( certLlave ) {
      unsigned char *aux = NULL;
      *tamCertLlave = BIO_get_mem_data(bioMem, &aux);
      memcpy(certLlave, aux, *tamCertLlave);
    } else
      *tamCertLlave = BIO_get_mem_data(bioMem, NULL);

    BIO_free(bioMem);
    bioMem = NULL;
    X509_free(x509Llave);
    x509Llave = NULL;
  }

  /*
   * Obtenemos los certificados raíz
   */

  if ( numCerts ) {

    *numCerts = sk_X509_num(ca);

    if (certs || tamCerts) {
      unsigned char *auxCertBuf;
      i = 0;
      while ((auxCert = sk_X509_pop(ca))) {
	bioMem = BIO_new(BIO_s_mem());
	BIO_set_close(bioMem, BIO_NOCLOSE);

	if ( !PEM_write_bio_X509(bioMem, auxCert) ) {
	  if ( tamLlavePrivada && llavePrivada ) {
	    CRYPTO_Random(*tamLlavePrivada, llavePrivada);
	    CRYPTO_Random(*tamLlavePrivada, llavePrivada);
	  }

	  return ERR_CW_SI;
	}

	tamCerts[i] = BIO_get_mem_data(bioMem, &auxCertBuf);
	if ( certs ) {
	  memcpy(certs,auxCertBuf,tamCerts[i]);
	  certs += tamCerts[i];
	}

	X509_free(auxCert);
	BIO_free(bioMem);
	bioMem = NULL;
	OPENSSL_free(auxCertBuf);
	++i;
      }
    }
  }


  return ERR_CW_NO;
}

/*! \brief Cifrado simétrico.
 *
 * Cifrado simétrico
 *
 * \param cryptoKey
 *        La llave de cifrado
 *
 * \param padding
 *        Indica si realizar padding pkcs#5 (1) o no (0).
 *
 * \param algoritmo
 *        El algoritmo de cifrado a utilizar.
 *
 * \param bloqueClaro
 *        El buffer a cifrar.
 *
 * \param tamBloqueClaro
 *        El tamaño en bytes de bloqueClaro
 *
 * \param bloqueCifrado
 *        El buffer cifrado
 *
 * \param tamBloqueCifrado
 *        El tamaño, en bytes, del bloque cifrado.
 *
 * \retval 0
 *         Ok
 *
 * \retval != 0
 *         Error
 */

int CRYPTO_Cifrar ( CRYPTO_KEY *cryptoKey,  int padding,  int algoritmo,  unsigned char *bloqueClaro, 
    int tamBloqueClaro,  unsigned char *bloqueCifrado,  int *tamBloqueCifrado)
{
  EVP_CIPHER_CTX ctx;
  int tamSalida, auxTam;

  unsigned char *iv;
  int i;
  EVP_CIPHER *cipher = NULL;

  cipher = tablaAlgoritmos[algoritmo];

  if ( !bloqueCifrado ) {
    *tamBloqueCifrado = tamBloqueClaro + EVP_CIPHER_block_size(cipher);
    return ERR_CW_NO;
  }

  iv = (unsigned char *) OPENSSL_malloc (EVP_CIPHER_iv_length(cipher));
  if (!iv)
    return ERR_CW_OUT_OF_MEMORY;

  for ( i = 0 ; i < EVP_CIPHER_iv_length(cipher) ; i++ )
    iv[i] = 0;

  EVP_CIPHER_CTX_init(&ctx);

  if ( !EVP_CipherInit_ex(&ctx, cipher, NULL, cryptoKey->llavePrivada, iv, CRYPTO_CIFRAR) ) {
    OPENSSL_free(iv);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  EVP_CIPHER_CTX_set_padding(&ctx, padding);

  if ( !EVP_CipherUpdate(&ctx, bloqueCifrado, &auxTam, bloqueClaro, tamBloqueClaro) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    OPENSSL_free(iv);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  if ( ! EVP_CipherFinal_ex(&ctx, bloqueCifrado + auxTam, &tamSalida) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    OPENSSL_free(iv);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  (*tamBloqueCifrado) = tamSalida + auxTam;

  EVP_CIPHER_CTX_cleanup(&ctx);

  OPENSSL_free(iv);
  iv = NULL;

  return ERR_CW_NO;
}



/*! \brief Descifrado simétrico.
 *
 * Descifrado simétrico.
 *
 * \param cryptoKey
 *        La llave de descifrado.
 *
 * \param padding
 *        Indica si se utilizó o no padding PKCS#5 en el cifrado
 *
 * \param algoritmo
 *        El algoritmo simétrico de descifrado.
 *
 * \param bloqueCifrado
 *        El buffer cifrado
 *
 * \param tamBloqueCifrado
 *        El tamaño de bloqueCifrado en bytes
 *
 * \param bloqueDescifrado
 *        El buffer descifrado.
 *
 * \param tamBloqueDescifrado
 *        El tamaño, en bytes, de bloqueDescifrado
 *
 * \retval 0
 *         Ok
 *
 * \retval != 0
 *         Error
 */

int CRYPTO_Descifrar ( CRYPTO_KEY *cryptoKey,  int padding,  int algoritmo,  unsigned char *bloqueCifrado, 
    int tamBloqueCifrado,  unsigned char *bloqueDescifrado,  int *tamBloqueDescifrado)
{
  EVP_CIPHER_CTX ctx;
  unsigned char *iv;
  int tamSalida, auxTam;
  int i;
  EVP_CIPHER *cipher = NULL;

  cipher = tablaAlgoritmos[algoritmo];

  /*
   * Si bloqueDescifrado es NULL entonces devolvemos el tamaño máximo
   * posible que puede ocupar el buffer descifrado.
   */

  if ( !bloqueDescifrado) {
    *tamBloqueDescifrado = tamBloqueCifrado + EVP_CIPHER_block_size(cipher);
    return ERR_CW_NO;
  }

  /*
   * Vector de inicialización a piño fijo
   */

  iv = (unsigned char *) OPENSSL_malloc (EVP_CIPHER_iv_length(cipher));
  
  if ( ! iv )
    return ERR_CW_OUT_OF_MEMORY;

  for ( i = 0 ; i < EVP_CIPHER_iv_length(cipher) ; i++ )
    iv[i] = 0;

  EVP_CIPHER_CTX_init(&ctx);

  if ( !EVP_CipherInit_ex(&ctx, cipher, NULL, cryptoKey->llavePrivada, iv, CRYPTO_DESCIFRAR) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    OPENSSL_free(iv);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  EVP_CIPHER_CTX_set_padding(&ctx, padding);

  if ( !EVP_CipherUpdate(&ctx, bloqueDescifrado, &auxTam, bloqueCifrado, tamBloqueCifrado) ) {
    OPENSSL_free(iv);
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  if ( ! EVP_CipherFinal_ex(&ctx, bloqueDescifrado + auxTam, &tamSalida) ) {
    EVP_CIPHER_CTX_cleanup(&ctx);
    OPENSSL_free(iv);
    return ERR_CW_IMPOSIBLE_DESCIFRAR_BLOQUE;
  }

  (*tamBloqueDescifrado) = auxTam + tamSalida;

  EVP_CIPHER_CTX_cleanup(&ctx);

  OPENSSL_free(iv);
  iv = NULL;

  return ERR_CW_NO;

}

/*! \brief Reserva memoria para un nuevo objeto CRYPTO_KEY.
 *
 * Reserva memoria para un nuevo objecto CRYPTO_KEY.
 *
 * \param algoritmo
 *        El algoritmo simétrico para el que generamos la llave.
 *
 * \param cryptoKey
 *        La llave generada.
 *
 * \retval 0
 *         Ok
 *
 * \retval != 0
 *         Error
 */

int CRYPTO_KEY_New  ( int algoritmo,  CRYPTO_KEY *cryptoKey)
{
  EVP_CIPHER *alg = NULL;

  alg = tablaAlgoritmos[algoritmo];

  cryptoKey->llavePrivada = (unsigned char *) OPENSSL_malloc(EVP_CIPHER_key_length(alg));
  if ( ! (cryptoKey->llavePrivada) )
    return ERR_CW_OUT_OF_MEMORY;

#ifdef WIN32
  if ( !VirtualLock(cryptoKey->llavePrivada, EVP_CIPHER_key_length(alg)) ) {
    OPENSSL_free(cryptoKey->llavePrivada);
    cryptoKey->llavePrivada = NULL;
    return ERR_CW_SI;
  }
#endif

  CRYPTO_Random(EVP_CIPHER_key_length(alg), cryptoKey->llavePrivada);
  cryptoKey->tamLlavePrivada = EVP_CIPHER_key_length(alg);

  return ERR_CW_NO;
}

/*! \brief Libera los recursos de una llave en formato interno
 *         de Crypto Wrappers.
 *
 * Libera los recursos de una llave en formato interno de Crypto
 * Wrappers.
 *
 * \param cryptoKey
 *        La llave a liberar
 *
 * \retval 0
 *         Ok
 */

int CRYPTO_KEY_Free ( CRYPTO_KEY *cryptoKey )
{
  CRYPTO_SecureZeroMemory(cryptoKey->llavePrivada, cryptoKey->tamLlavePrivada);

#ifdef WIN32
  VirtualUnlock(cryptoKey->llavePrivada, cryptoKey->tamLlavePrivada);
#endif

  OPENSSL_free(cryptoKey->llavePrivada);
  return ERR_CW_NO;
}

/*! \brief Establece una llave a formato interno de Crypto Wrapper.
 *
 * Establece una llave a formato interno de Crypto Wrappers.
 *
 * \param cryptoKey
 *        La llave que será el formato de salida.
 *
 * \param llavePrivada
 *        La llave de entrada
 *
 * \param tamLlavePrivada
 *        El tamaño de llavePrivada en bytes
 *
 * \retval 0
 *         Ok
 *
 * \retval 1
 *         Error
 */

int CRYPTO_Key_Set  ( CRYPTO_KEY *cryptoKey,  unsigned char *llavePrivada,  int tamLlavePrivada)
{
  if ( tamLlavePrivada > cryptoKey->tamLlavePrivada )
    return ERR_CW_SI;

  memcpy(cryptoKey->llavePrivada, llavePrivada, tamLlavePrivada);
  CRYPTO_SecureZeroMemory(llavePrivada, tamLlavePrivada);

  return ERR_CW_NO;
}

/*! \brief Cambiar el byte order de un buffer.
 *
 * Cambia el byte order de un buffer.
 *
 * \param in
 *        Es de entrada/salida. Como entrada es el buffer
 *        a invertir. Tras finalizar la función obtenemos
 *        el buffer con los bytes invertidos.
 *
 * \param tamIn
 *        El tamaño de in.
 *
 */

void CRYPTO_ByteOrder (unsigned char *in, int tamIn)
{
  register int i,j;
  unsigned char aux;

  i = 0;
  j = tamIn-1;
  while ( i < j ) {
    aux = in[i];
    in[i] = in[j];
    in[j] = aux;
    ++i;
    --j;
  }

}

/*! \brief Calcula el identificador de un llave en formato interno
 *         de OpenSSL.
 *
 * Calcula el identificador de una llave en formato interno de
 * OpenSSL.
 *
 * \param evp
 *        La llave en formato i
 *
 * \param id
 *        El identificador calculado para la llave
 *
 * \retval 1
 *         Error
 *
 * \retval 0
 *         Ok
 */

int CRYPTO_EVPPKEY_Id (EVP_PKEY *evp, unsigned char id[20])
{
  int tamE, tamN, resto = 0;
  unsigned char *e,*n;

  EVP_MD_CTX mdCtx;

  tamE = BN_num_bytes(evp->pkey.rsa->e);

  if ( tamE < 4 ) {
    resto = 4-tamE;
    tamE = 4;
  }

  e = (unsigned char *) malloc (tamE);
  if ( !e )
    return ERR_CW_SI;
  memset(e, 0, tamE);
  BN_bn2bin(evp->pkey.rsa->e, e+resto);

  tamN = BN_num_bytes(evp->pkey.rsa->n);
  n = (unsigned char *) malloc (tamN);
  if ( !n ) {
    free(e);
    return ERR_CW_SI;
  }
  BN_bn2bin(evp->pkey.rsa->n, n);

  /* Pasamos a little endian */

  CRYPTO_ByteOrder(n,tamN);
  CRYPTO_ByteOrder(e,tamE);

  /* Calculamos el id */

  EVP_MD_CTX_init(&mdCtx);

  if  (!EVP_DigestInit_ex(&mdCtx, EVP_sha1(), NULL) ) {
    EVP_MD_CTX_cleanup(&mdCtx);
    free(n);
    free(e);
    return ERR_CW_SI;
  }

  if ( !EVP_DigestUpdate(&mdCtx, n, tamN) ) {
    EVP_MD_CTX_cleanup(&mdCtx);
    free(n);
    free(e);
    return ERR_CW_SI;
  }

  free(n);

  if ( !EVP_DigestUpdate(&mdCtx, e, tamE) ) {
    EVP_MD_CTX_cleanup(&mdCtx);
    free(e);
    return ERR_CW_SI;
  }

  free(e);

  if ( !EVP_DigestFinal_ex(&mdCtx, id, NULL) ) {
    EVP_MD_CTX_cleanup(&mdCtx);
    return ERR_CW_SI;
  }

  EVP_MD_CTX_cleanup(&mdCtx);

  return ERR_CW_NO;
}

/*! \brief Calcula el identificador de una llave en formato PEM.
 *
 * Calcula el identificador de una llave en formato PEM
 *
 * \param llavePEM
 *        La llave en formato PEM.
 *
 * \param tam
 *        El tamaño en bytes de llavePEM
 *
 * \param privada
 *        Indica si llavePEM es una llave privada (1) o pública
 *        (0)
 *
 * \param pwd
 *        La password que protege la llave privada. Debe ser NULL
 *        cuando llavePEM es pública.
 *
 * \param id
 *        El identificador de llave calculado
 *
 * \retval 1
 *         Error
 *
 * \retval 0
 *         Ok
 */

int CRYPTO_LLAVE_PEM_Id (unsigned char *llavePEM, unsigned long tam, 
    int privada, char * pwd, unsigned char id[20])
{
  BIO *bioMem;
  EVP_PKEY *llave;
  RSA *llaveRSA;

  int err;

  bioMem = BIO_new_mem_buf(llavePEM, tam);
  if ( !bioMem )
    return 1;

  if ( privada ) {

    if ( pwd )
      llave = PEM_read_bio_PrivateKey(bioMem,NULL,OSSL_PasswordCallback, pwd);
    else
      llave = PEM_read_bio_PrivateKey(bioMem,NULL,NULL, NULL);

    if ( !llave ) {
      BIO_free(bioMem);
      return 1;
    }

  } else {

    llaveRSA = PEM_read_bio_RSAPublicKey(bioMem,NULL,NULL,NULL);
    llave = EVP_PKEY_new();

    if ( ! llave ) {
      BIO_free(bioMem);
      return ERR_CW_OUT_OF_MEMORY;
    }

    EVP_PKEY_assign_RSA(llave,llaveRSA);
    if ( !llave ) {
      BIO_free(bioMem);
      return 1;
    }
  }

  BIO_free(bioMem);

  err = CRYPTO_EVPPKEY_Id (llave, id);
  EVP_PKEY_free(llave);

  return err;
}

/*! \brief Calcula el identificador de llave asociado a un certificado.
 *
 * Calcula el identificador de llave asociado a un certificado. Nótese que este
 * identificador no tiene nada que ver con el Subject Key Identifier, sino con
 * el identificador que se añade a los bloque del Clauer para localizar llaves
 *
 * \param certPEM
 *        El certificado en formato PEM
 * 
 * \param tam
 *        El tamaño en bytes de certPEM 
 *
 * \param id
 *        El identificador de la llave calculado
 *
 * \retval 0
 *         Ok
 *
 * \retval 1
 *         Error
 */

int CRYPTO_CERT_PEM_Id (unsigned char *certPEM, unsigned long tam, unsigned char id[20])
{
  BIO *bioMem;
  X509 *cert;
  EVP_PKEY *llave;

  bioMem = BIO_new_mem_buf(certPEM, tam);
  if ( !bioMem )
    return ERR_CW_SI;

  cert = PEM_read_bio_X509(bioMem, NULL,NULL,NULL);
  if ( !cert ) {
    BIO_free(bioMem);
    return ERR_CW_SI;
  }

  BIO_free(bioMem);

  llave = X509_get_pubkey(cert);
  if ( !llave ) {
    BIO_free(bioMem);
    return ERR_CW_SI;
  }

  return CRYPTO_EVPPKEY_Id (llave, id);
}

/*! \brief Convierte una llave en formato pem a formato interno
 *         de OpenSSL.
 *
 * Convierte una llave en formato pem a formato interno de OpenSSL.
 * 
 * \param llave
 *        La llave privada en formato PEM.
 *
 * \param tamLlave
 *        El tamaño de la llave en bytes
 * 
 * \param privada
 *        Indica si se trata de una llave privada (1) o de una
 *        llave pública (0).
 *
 * \param pwd
 *        La password que protege la llave privada. Si privada
 *        en 0 pwd debe ser NULL.
 *
 * \retval NULL
 *         Error
 *
 * \retval !=NULL
 *         La llave en formato i
 */

EVP_PKEY * CRYPTO_PEM2EVP_PKEY (unsigned char *llave,
    unsigned long tamLlave,
    int privada,
    char * pwd)
{

  BIO *bioMem;
  EVP_PKEY *evpLlave = NULL;

  bioMem = BIO_new_mem_buf((void *)llave,tamLlave);

  if  (!bioMem)
    return NULL;

  if ( privada ) {

    if ( pwd ) {
      if ( !PEM_read_bio_PrivateKey(bioMem,&evpLlave,OSSL_PasswordCallback,(void *)pwd) ) {
	BIO_free(bioMem);
	return NULL;
      }
    } else {
      if ( !PEM_read_bio_PrivateKey(bioMem,&evpLlave,NULL,NULL) ) {
	BIO_free(bioMem);
	return NULL;
      }
    }

  } else {
    RSA *rsaLlave = NULL;

    if ( !PEM_read_bio_RSAPublicKey(bioMem,&rsaLlave,NULL,NULL) ) {
      BIO_free(bioMem);
      return NULL;
    }
    evpLlave = EVP_PKEY_new();
    if ( !evpLlave ) {
      BIO_free(bioMem);
      RSA_free(rsaLlave);
      return NULL;
    }
    if ( !EVP_PKEY_assign_RSA(evpLlave, rsaLlave) ) {
      EVP_PKEY_free(evpLlave);
      BIO_free(bioMem);
      return NULL;
    }
  }

  BIO_free(bioMem);

  return evpLlave;
}

/*! \brief Convierte un certificado en formato PEM a formato interno
 *         de OpenSSL.
 *
 * Convierte un certificado en formato PEM a formato interno de OpenSSL.
 *
 * \param cert
 *        El certificado en formato PEM a convertir.
 *
 * \param tamCert
 *        El tamaño de cert en bytes.
 *
 * \retval NULL
 *         Error
 *
 * \retval !=NULL
 *         El certificado en formato i
 */

X509 *CRYPTO_PEM2X509 (unsigned char *cert,
    unsigned long tamCert)
{
  BIO *bioMem;
  X509 *x509Cert = NULL;


  bioMem = BIO_new_mem_buf((void *)cert, tamCert);
  if ( !bioMem )
    return NULL;


  x509Cert = PEM_read_bio_X509(bioMem,NULL,NULL,NULL);
  if ( !x509Cert ) {
    BIO_free(bioMem);
    return NULL;
  }

  BIO_free(bioMem);
  return x509Cert;
}

/*! \brief Convierte un pkcs#12 en formato interno de OpenSSL a formato DER.
 *
 * Convierte un pkcs#12 en formato interno de OpenSSL a formato DER.
 *
 * \param p12
 *        El pkcs#12 en formato interno.
 *
 * \param pkcs12
 *        El buffer de salida en formato DER.
 *
 * \param tamPCKS12
 *        El tamaño, en bytes, de pkcs12.
 *
 * \retval 0
 *         Error
 * 
 * \retval 1
 *         Ok
 */

int CRYPTO_PKCS122DER (PKCS12 *p12,unsigned char *pkcs12, unsigned long *tamPKCS12)
{
  BIO *bioMem;
  char *aux;

  bioMem = BIO_new(BIO_s_mem());
  if ( !bioMem )
    return 0;

  if ( !i2d_PKCS12_bio(bioMem,p12) ) {
    BIO_free(bioMem);
    return 0;
  }

  *tamPKCS12 = BIO_get_mem_data(bioMem,&aux);

  if ( pkcs12 )
    memcpy(pkcs12, aux, *tamPKCS12);

  BIO_free(bioMem);

  return 1;
}

/*! \brief Crea un nuevo pkcs#12.
 *
 * Crea un nuevo pkcs#12.
 *
 * \param llavePrivada
 *        La llave privada en formato PEM que se incluirá
 *        en el mismo.
 *
 * \param tamPrivada
 *         Tamaño de llavePrivada en formato PEM.
 *
 * \param pwdLlavePrivada
 *        La password que protege la llave privada
 *        o NULL si la llave está sin cifrar.
 *
 * \param certAsociado
 *        Certificado asociado a la llave privada.
 *        En formato PEM.
 *
 * \param tamCert
 *        Tamaño de certAsociado.
 *
 * \param certsRaiz
 *        Array conteniendo todas las CAs que
 *        queramos añadir. Todos los certificados
 *        irán en formato PEM.
 *
 * \param tamCertsRaiz
 *        El tamaño, en bytes, de certsRaiz.
 *
 * \param numRaiz
 *        Indica el número de certificados presentes
 *        en certsRaiz
 *
 * \param pwd
 *        La contraseña que protegerá el pkcs#12
 *
 * \param friendlyName
 *        El friendlyName del pkcs#12
 *
 * \param pkcs12
 *        El buffer que contendrá el pkcs#12. Puede
 *        ser NULL para poder obtener el tamaño del
 *        mismo.
 *
 * \param tamPKCS12
 *        El tamaño, en bytes, del pkcs#12.
 *
 * \retval 0
 *         Ok
 *
 * \retval 1
 *         Error
 */

int CRYPTO_PKCS12_Crear (unsigned char *llavePrivada,
    unsigned long tamPrivada,
    char * pwdLlavePrivada,
    unsigned char *certAsociado,
    unsigned long tamCert,
    unsigned char *certsRaiz,
    unsigned long *tamCertsRaiz,
    int numRaiz,
    char * pwd,
    char *friendlyName,
    unsigned char *pkcs12,
    unsigned long *tamPKCS12)
{
  PKCS12 *p12;
  EVP_PKEY *evpLlave;
  X509 *x509, *aux;
  register int i;

  STACK_OF(X509) *skX509;


  evpLlave = CRYPTO_PEM2EVP_PKEY(llavePrivada, tamPrivada, 1,pwdLlavePrivada);
  if  (!evpLlave)
    return 1;

  x509 = CRYPTO_PEM2X509(certAsociado,tamCert);
  if ( !x509 ) {
    EVP_PKEY_free(evpLlave);
    return 1;
  }

  skX509 = sk_X509_new(NULL);

  for ( i = 0 ; i < numRaiz ; i++ ) {
    aux = CRYPTO_PEM2X509(certsRaiz,tamCertsRaiz[i]);
    if ( !aux ) {
      sk_X509_free(skX509);
      EVP_PKEY_free(evpLlave);
      X509_free(x509);
      return 1;
    }
    sk_X509_push(skX509,aux);
  }


  p12 = PKCS12_create(pwd,friendlyName,evpLlave,x509,skX509,0,0,0,0,0);

  if (!p12) {
    sk_X509_free(skX509);
    EVP_PKEY_free(evpLlave);
    X509_free(x509);
    return 1;
  }

  if ( !CRYPTO_PKCS122DER(p12,pkcs12,tamPKCS12) ) {
    sk_X509_free(skX509);
    EVP_PKEY_free(evpLlave);
    X509_free(x509);
    PKCS12_free(p12);
    return 1;		
  }

  sk_X509_free(skX509);
  EVP_PKEY_free(evpLlave);
  X509_free(x509);

  return 0;
}

/*! \brief Reserva memoria para un nombre distintivo.
 *
 * Reserva memoria para un nombre distintivo.
 *
 * \retval NULL
 *         Error
 *
 * \retval != NULL
 *         El nuevo nombre distintivo
 *
 */

DN *CRYPTO_DN_New (void)
{
  DN *dn;
  dn = (DN *) malloc (sizeof(DN));
  if (!dn)
    return NULL;

  dn->C     = NULL;
  dn->CN    = NULL;
  dn->email = NULL;
  dn->L     = NULL;
  dn->O     = NULL;
  dn->OU    = NULL;
  dn->ST    = NULL;

  return dn;
}

/*! \brief Libera un nombre distintivo
 *
 * Libera un nombre distintivo.
 *
 * \param dn
 *        El nombre distintivo a liberar
 *
 * \retval 1
 *         Ok
 */

int CRYPTO_DN_Free(DN *dn)
{
  CRYPTO_DN_Limpiar(dn);
  free(dn);

  return 1;
}


/*! \brief Libera la memoria de un nombre distintivo.
 *
 * Libera la memoria de un nombre distintivo.
 *
 * \param dn
 *        El nombre distintivo a liberar.
 *
 * \retval 1
 *         Ok
 */

int CRYPTO_DN_Limpiar(DN *dn)
{

  if ( dn->C )
    free(dn->C);
  if ( dn->CN )
    free(dn->CN);
  if ( dn->email )
    free(dn->email);
  if ( dn->L )
    free(dn->L);
  if ( dn->O )
    free(dn->O);
  if ( dn->OU )
    free(dn->OU);
  if ( dn->ST )
    free(dn->ST);

  return 1;

}

/*! \brief Obtiene el subject y el issuer de un certificado.
 *
 * Obtiene en subject e issuer de un certificado.
 *
 * \param cert
 *        El certificado en formato PEM.
 *
 * \param tamCert
 *        El tamaño de cert en bytes.
 *
 * \param subject
 *        [SALIDA] El subject del certificado.
 *
 * \param issuer
 *        [SALIDA] El issuer del certificado
 *
 * \retval 0
 *         Error
 *
 * \retval 1
 *         Ok
 */

int CRYPTO_CERT_SubjectIssuer (unsigned char *cert, unsigned long tamCert, DN *subject, DN *issuer)
{

  X509 *x509;
  X509_NAME *dn;
  int tam,aux=0;
  int hacerSubject = 1;
  DN *auxDN;

  x509 = CRYPTO_PEM2X509(cert, tamCert);
  if ( !cert )
    return 0;


  while ( aux != 2 ) {

    if ( hacerSubject ) {

      if ( !subject ) {
	++aux;
	hacerSubject = 0;
	continue;
      }

      dn = X509_get_subject_name(x509);

      if  (!dn) {
	X509_free(x509);
	return 0;
      }

      auxDN = subject;

    } else {

      if ( !issuer )
	break;

      dn = X509_get_issuer_name(x509);
      if ( !dn ) {
	CRYPTO_DN_Limpiar(subject);
	X509_free(x509);
	return 0;
      }
      auxDN = issuer;
    }

    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_commonName, NULL, 0)) != -1 ) {	
      auxDN->CN = (char *) malloc (tam+1);
      if ( ! auxDN->CN ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;			
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_commonName, auxDN->CN, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }


    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_countryName, NULL, 0)) != -1 ) {
      auxDN->C = (char *) malloc (tam+1);
      if ( ! auxDN->C ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;			
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_countryName, auxDN->C, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }

    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_localityName, NULL, 0)) != -1 ) {
      auxDN->L = (char *) malloc (tam+1);
      if ( ! auxDN->L ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;			
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_localityName, auxDN->L, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }

    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_stateOrProvinceName, NULL, 0)) != -1 ) {
      auxDN->ST = (char *) malloc (tam+1);
      if ( ! auxDN->ST ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_stateOrProvinceName, auxDN->ST, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }

    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_organizationName, NULL, 0)) != -1 ) {
      auxDN->O = (char *) malloc (tam+1);
      if ( ! auxDN->O ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;			
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_organizationName, auxDN->O, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }


    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_organizationalUnitName, NULL, 0)) != -1 ) {
      auxDN->OU = (char *) malloc (tam+1);
      if ( ! auxDN->OU ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;			
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_organizationalUnitName, auxDN->OU, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }


    if ( (tam = X509_NAME_get_text_by_NID (dn, NID_pkcs9_emailAddress, NULL, 0)) != -1 ) {
      auxDN->email = (char *) malloc (tam+1);
      if ( ! auxDN->email ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;			
      }
      if ( (tam = X509_NAME_get_text_by_NID (dn, NID_pkcs9_emailAddress, auxDN->email, tam+1)) == -1 ) {
	CRYPTO_DN_Limpiar(subject);
	CRYPTO_DN_Limpiar(issuer);
	X509_free(x509);
	X509_NAME_free(dn);
	return 0;
      }
    }

    hacerSubject = 0;
    ++aux;

  }

  return 1;

}

/*! \brief Compara dos nombre distintivos e indica si
 *         son iguales o no.
 *
 * Compara dos nombres distintivos e indica si son iguales
 * o no.
 *
 * \param dn1
 *        Primer nombre distintivo
 *
 * \param dn2
 *        Segundo nombre distintivo
 *
 * \retval 0
 *         Son distintos
 *
 * \retval 1
 *         Son iguales
 *
 */

int CRYPTO_DN_Igual (DN *dn1, DN*dn2)
{
  if ( (dn1->C != NULL) && (dn2->C != NULL ) ) {
    if ( strcmp(dn1->C, dn2->C) != 0 ) 
      return 0;
  } else if ( (dn1->C != NULL) && (dn2->C == NULL ) ) {
    return 0;
  } else if ( (dn1->C == NULL) && (dn2->C != NULL) ) {
    return 0;
  }

  if ( (dn1->CN != NULL) && (dn2->CN != NULL ) ) {
    if ( strcmp(dn1->CN, dn2->CN) != 0 ) 
      return 0;
  } else if ( (dn1->CN != NULL) && (dn2->CN == NULL ) ) {
    return 0;
  } else if ( (dn1->CN == NULL) && (dn2->CN != NULL) ) {
    return 0;
  }

  if ( (dn1->email != NULL) && (dn2->email != NULL ) ) {
    if ( strcmp(dn1->email, dn2->email) != 0 ) 
      return 0;
  } else if ( (dn1->email != NULL) && (dn2->email == NULL ) ) {
    return 0;
  } else if ( (dn1->email == NULL) && (dn2->email != NULL) ) {
    return 0;
  }

  if ( (dn1->L != NULL) && (dn2->L != NULL ) ) {
    if ( strcmp(dn1->L, dn2->L) != 0 ) 
      return 0;
  } else if ( (dn1->L != NULL) && (dn2->L == NULL ) ) {
    return 0;
  } else if ( (dn1->L == NULL) && (dn2->L != NULL) ) {
    return 0;
  }

  if ( (dn1->O != NULL) && (dn2->O != NULL ) ) {
    if ( strcmp(dn1->O, dn2->O) != 0 ) 
      return 0;
  } else if ( (dn1->O != NULL) && (dn2->O == NULL ) ) {
    return 0;
  } else if ( (dn1->O == NULL) && (dn2->O != NULL) ) {
    return 0;
  }

  if ( (dn1->OU != NULL) && (dn2->OU != NULL ) ) {
    if ( strcmp(dn1->OU, dn2->OU) != 0 ) 
      return 0;
  } else if ( (dn1->OU != NULL) && (dn2->OU == NULL ) ) {
    return 0;
  } else if ( (dn1->OU == NULL) && (dn2->OU != NULL) ) {
    return 0;
  }

  if ( (dn1->ST != NULL) && (dn2->ST != NULL ) ) {
    if ( strcmp(dn1->ST, dn2->ST) != 0 ) 
      return 0;
  } else if ( (dn1->ST != NULL) && (dn2->ST == NULL ) ) {
    return 0;
  } else if ( (dn1->ST == NULL) && (dn2->ST != NULL) ) {
    return 0;
  }


  return 1;
}




/*! \brief Transforma una llave privada en formato PEM a un PRIVATEKEYBLOB de
 *         Microsoft Crypto API.
 *
 * Transforma una llave privada en formato PEM a un PRIVATEKEYBLOB de 
 * Microsoft Crypto API
 *
 * \param llavePrivada
 *        La llave privada en formato PEM
 *
 * \param tamLlavePrivada
 *        El tamaño, en bytes, de la llave privada
 * 
 * \param pwd
 *        La password que protege la llave privada. Puede valer NULL
 *        si la llave no está cifrada.
 *
 * \param alg
 *        El algoritmo que se especificará en el blob. Puede ser
 *        CALG_SIGN o CALG_KEYX.
 *
 * \param blob
 *        El buffer de salida. Puede ser NULL en cuyo caso únicamente
 *        se devuelve el parámetro tamBlob.
 *
 * \param tamBlob
 *        El tamaño, en bytes, de blob.
 *
 * \retval 1
 *         Ok
 *
 * \retval 0
 *         Error
 */

int CRYPTO_LLAVE2BLOB (unsigned char *llavePrivada, unsigned long tamLlavePrivada,
    char * pwd, unsigned long alg, unsigned char *blob, 
    unsigned long *tamBlob)
{
  EVP_PKEY *evpLlave;
  long tamN, resto=0;
  unsigned char *aux;

  aux = blob;
  evpLlave = CRYPTO_PEM2EVP_PKEY (llavePrivada,tamLlavePrivada,1,pwd);

  if ( !evpLlave )
    return 0;

  tamN = BN_num_bytes(evpLlave->pkey.rsa->n);

  *tamBlob = sizeof(BLOBHEADER) + 
    sizeof(RSAPUBKEY) + 
    9*tamN/2;

  if ( !blob ) {
    EVP_PKEY_free(evpLlave);
    return 1;
  }

  /* Construimos el blob
   */

  memset(blob,0,*tamBlob);

  tamN = BN_num_bytes(evpLlave->pkey.rsa->n);

  ((BLOBHEADER *) blob)->bType = PRIVATEKEYBLOB;
  ((BLOBHEADER *) blob)->bVersion = 0x02;
  ((BLOBHEADER *) blob)->reserved = 0;
  ((BLOBHEADER *) blob)->aiKeyAlg = alg;
  blob += sizeof(BLOBHEADER);

  ((RSAPUBKEY *) blob)->magic = 0x32415352;
  ((RSAPUBKEY *) blob)->bitlen = tamN*8;

  ((RSAPUBKEY *) blob)->pubexp = 0;
  BN_bn2bin(evpLlave->pkey.rsa->e,(unsigned char *) &(((RSAPUBKEY *) blob)->pubexp));
  CRYPTO_ByteOrder((unsigned char *) &(((RSAPUBKEY *) blob)->pubexp),
      BN_num_bytes(evpLlave->pkey.rsa->e));

  blob += sizeof(RSAPUBKEY);

  BN_bn2bin(evpLlave->pkey.rsa->n, blob);
  CRYPTO_ByteOrder(blob, tamN);
  blob += tamN;

  resto = tamN/2 - BN_num_bytes(evpLlave->pkey.rsa->p);
  BN_bn2bin(evpLlave->pkey.rsa->p, blob+resto);
  CRYPTO_ByteOrder(blob, tamN/2);
  blob += tamN/2;

  resto = tamN/2 - BN_num_bytes(evpLlave->pkey.rsa->q);
  BN_bn2bin(evpLlave->pkey.rsa->q, blob+resto);
  CRYPTO_ByteOrder(blob,tamN/2);
  blob += tamN/2;

  resto = tamN/2 - BN_num_bytes(evpLlave->pkey.rsa->dmp1);
  BN_bn2bin(evpLlave->pkey.rsa->dmp1, blob+resto);
  CRYPTO_ByteOrder(blob,tamN/2);
  blob += tamN/2;

  resto = tamN/2 - BN_num_bytes(evpLlave->pkey.rsa->dmq1);
  BN_bn2bin(evpLlave->pkey.rsa->dmq1, blob+resto);
  CRYPTO_ByteOrder(blob,tamN/2);
  blob += tamN/2;

  resto = tamN/2 - BN_num_bytes(evpLlave->pkey.rsa->iqmp);
  BN_bn2bin(evpLlave->pkey.rsa->iqmp, blob+resto);
  CRYPTO_ByteOrder(blob,tamN/2);
  blob += tamN/2;

  resto = tamN - BN_num_bytes(evpLlave->pkey.rsa->d);
  BN_bn2bin(evpLlave->pkey.rsa->d, blob+resto);
  CRYPTO_ByteOrder(blob,tamN);

  EVP_PKEY_free(evpLlave);

  return 1;

}


#ifndef WIN32
unsigned long OSSL_ThreadId (void)
{

  unsigned long ret;

  ret = (unsigned long) pthread_self();

  return ret;

}
#endif


/*! \brief Comprueba la password de un pkcs12
 *
 * Comprueba la password de un pkcs12
 *
 * \param pkcs12
 *        Un buffer con el pkcs#12
 *
 * \param tamPkcs12
 *        El tamaño de pkcs12 en bytes
 *
 * \param pwd
 *        La password que se utilizará para verificar
 *
 * \retval 0
 *         Password incorrecta
 *
 * \retval 1
 *         Password correcta
 * 
 * \retval 2
 *         Error
 */

int CRYPTO_PKCS12_VerificarPassword ( unsigned char *pkcs12,  unsigned long tamPkcs12,  char * pwd)
{

  BIO *bioMem = NULL;
  PKCS12 *p12 = NULL;
  int ok;

  /*
   * Obtengo el pkcs12 en formato interno
   */

  bioMem = BIO_new_mem_buf(pkcs12, tamPkcs12);

  if ( !bioMem )
    return 2;

  if ( !d2i_PKCS12_bio(bioMem, &p12) ) {
    BIO_free(bioMem);
    bioMem = NULL;
    return 2;
  }

  /*
   * Parseamos el monstruo
   */


  ok = PKCS12_parse(p12, pwd, NULL, NULL, NULL);

  BIO_free(bioMem);
  bioMem = NULL;
  PKCS12_free(p12);
  p12 = NULL;

  if ( ok )
    return 1;
  else
    return 0;

}




/*! \brief Cambia la password de un pkcs12.
 *
 * Cambia la password de un pkcs12.
 *
 * \param p12Original
 *		  El pkcs12 original para cambiar la password.
 *
 * \param tamP12Original
 *		  El tamaño del pkcs12 original.
 *
 * \param pwdOriginal
 *		  La password que protege el pkcs12 original
 *
 * \param pwdNueva
 *		  La nueva password a establecer.
 *
 * \param p12Nuevo
 *		  SALIDA. El nuevo pkcs12 con la password.
 *
 * \param tamP12Nuevo
 *		  SALIDA. El tamaño del pkcs12 nuevo.
 *
 * \retval 1
 *		   ERROR
 *
 * \retval 0
 *		   Ok
 */

int CRYPTO_PKCS12_CambiarPassword ( unsigned char *p12Original,  unsigned long tamP12,  char * pwdOriginal, char * pwdNueva)
{
  BIO *bioMem = NULL;
  PKCS12 *osslP12Orig;
  unsigned char *aux = NULL;
  unsigned long tam;

  if ( !p12Original )
    return 1;

  /*
   * Obtengo el pkcs12 en formato interno
   */

  bioMem = BIO_new_mem_buf(p12Original, tamP12);

  if ( !bioMem )
    return 2;


  osslP12Orig = d2i_PKCS12_bio(bioMem, NULL);

  if ( !osslP12Orig ) {
    BIO_free(bioMem);
    bioMem = NULL;
    return 1;
  }

  BIO_free(bioMem);
  bioMem = NULL;

  if ( !PKCS12_newpass(osslP12Orig, pwdOriginal, pwdNueva) ) {
    return 1;
  }

  bioMem = BIO_new(BIO_s_mem());

  if ( !bioMem ) 
    return 1;	

  if ( !i2d_PKCS12_bio(bioMem, osslP12Orig) ) {
    BIO_free(bioMem);
    bioMem = NULL;
    return 1;
  }

  tam = BIO_get_mem_data(bioMem, &aux);
  memcpy(p12Original, aux, tam);
  BIO_free(bioMem);
  bioMem = 0;

  /* Esto no debería pasar nunca, pero por si las moscas */

  if ( tam > tamP12 )
    return 1;


  return 0;

}

/*! \brief Indica si el certificado que le pasamos como parámetro es un certificado
 *         raíz.
 *
 * Indica si el certificado que le pasamos como parámetro es un certificado raíz.
 * Nuestro criterio se basa en el cumplimiento de una de estas características:
 *
 *			. Presenta una extensión BASIC_CONSTRAINTS con CA = 1 y
 *            subject e issuer concuerdan.
 *
 *			. Si no hay extensión BASIC_CONSTRAINTS entonces simplemente
 *			  tomamos que subject e issuer sean iguales.
 *
 * \param cert
 *		  El certificado en formato PEM.
 *
 * \param tamCert
 *		  El tamaño en bytes de cert
 *
 * \retval 0
 *		   No es certificado raíz
 *
 * \retval 1
 *		   Es certificado raíz
 *
 * \retval -1
 *		   Se produjo un error
 */

int CRYPTO_X509_EsRoot (unsigned char *cert, unsigned long tamCert)
{
  int ret = 0;
  BIO *bioMem = NULL;
  X509 *x509 = NULL;
  DN *subject=NULL, *issuer=NULL;
  BASIC_CONSTRAINTS *bs = NULL;
  int crit;

  bioMem = BIO_new_mem_buf(cert, tamCert);

  if ( !bioMem ) {
    ret = -1;
    goto finCRYPTO_X509_EsRoot;
  }

  x509 = PEM_read_bio_X509(bioMem, NULL, NULL, NULL);

  if ( !x509 ) {
    ret = -1;
    goto finCRYPTO_X509_EsRoot;
  }

  BIO_free(bioMem);
  bioMem = NULL;

  /* Si subject e issuer son distintos, entonces no es root
   */

  subject = CRYPTO_DN_New();

  if ( !subject ) {
    ret = -1;
    goto finCRYPTO_X509_EsRoot;
  }

  issuer = CRYPTO_DN_New();

  if ( !issuer ) {
    ret = -1;
    goto finCRYPTO_X509_EsRoot;
  }

  if ( !CRYPTO_CERT_SubjectIssuer(cert, tamCert, subject, issuer) ) {
    ret = -1;
    goto finCRYPTO_X509_EsRoot;
  }

  if ( !CRYPTO_DN_Igual(subject, issuer) ) {
    ret = 0;
    goto finCRYPTO_X509_EsRoot;
  } 

  CRYPTO_DN_Free(subject);
  CRYPTO_DN_Free(issuer);
  subject = NULL;
  issuer = NULL;

  /* De momento asumimos que es un certificado raíz.
   * Ahora vamos a comprobar la extensión BASIC_CONSTRAINTS.
   */

  ret = 1;

  bs = X509_get_ext_d2i(x509, NID_basic_constraints, NULL, &crit);

  if ( bs == NULL ) {

    /* si devuelve NULL puede ser debido a un error o bien
     * que la extensión no esté presente
     */

    if ( crit == -1 ) {
      /* La extensión no se encontró. Por lo tanto,
       * el certificado es raiz
       */

      ret = 1;
      goto finCRYPTO_X509_EsRoot;

    } else if ( crit == -2 ) {

      /* La extensión aparece más de una vez. Esto creo que
       * no tiene mucha lógica, al menos en este caso, de modo
       * que devuelvo error de momento
       */

      ret = -1;
      goto finCRYPTO_X509_EsRoot;

    } else {

      /* No se pudo parsear la extensión, así es que a la porra
       */

      ret = -1;
      goto finCRYPTO_X509_EsRoot;

    }
  } else {

    /* Ha parseado correctamente la extensión. Comprobamos el valor de CA
     */

    if ( bs->ca )
      ret = 1;
    else
      ret = 0;

    goto finCRYPTO_X509_EsRoot;

  }


finCRYPTO_X509_EsRoot:


  if ( bioMem ) {
    BIO_free(bioMem);
    bioMem = NULL;
  }

  if ( x509 ) {
    X509_free(x509);
    x509 = NULL;
  }

  if ( subject ) {
    CRYPTO_DN_Free(subject);
    subject = NULL;
  }

  if ( issuer ) {
    CRYPTO_DN_Free(issuer);
    issuer = NULL;
  }

  if ( bs ) {
    BASIC_CONSTRAINTS_free(bs);
    bs = NULL;
  }

  return ret;

}

/*! \brief Indica si un certificado se corresponde con una clave privada.
 *
 *
 * \param cert
 *		  El certificado en formato PEM.
 *
 * \param tamCert
 *		  El tamaño en bytes de cert
 *
 * \param llavePrivada
 *		  La llave privada en formato PEM.
 *
 * \param tamCert
 *		  El tamaño en bytes de la llave privada
 *
 * \retval 0
 *		   No es se corresponden
 *
 * \retval 1
 *		   Se corresponden
 */

int CRYPTO_X509_LLAVE(unsigned char *cert, unsigned long tamCert, unsigned char *llavePrivada, unsigned long tamLlavePrivada, char *pwd){
	int ret;
	X509 *c = NULL;
	EVP_PKEY *k = NULL;
	
	c = CRYPTO_PEM2X509(cert, tamCert);
	k = CRYPTO_PEM2EVP_PKEY(llavePrivada, tamLlavePrivada, 1, pwd);
	ret = X509_check_private_key(c,k);
	EVP_PKEY_free(k);
	X509_free(c);
	return ret;
}

/*! \brief Compara dos certificados
 *
 * Compara dos certificados.
 *
 * \param cert_a
 *        Primer certificado en formato PEM
 *
 * \param tamCertA
 *        Tamaño de cert_a en bytes
 *
 * \param cert_b
 *        Segundo certificado en formato PEM
 *
 * \param tamCertB
 *        Tamaño de cert_b
 *
 * \retval 0
 *         Los certificados son iguales
 *
 * \retval 1
 *         Los certificados son distintos
 * 
 * \retval 2
 *         Error
 */

int CRYPTO_CERT_Cmp ( unsigned char *cert_a,  unsigned long tamCertA,
    unsigned char *cert_b,  unsigned long tamCertB)
{

  X509 *x509_a=NULL, *x509_b=NULL;
  int ret = 0;

  x509_a = CRYPTO_PEM2X509 (cert_a, tamCertA);
  if ( !x509_a ) {
    ret = 2;
    goto finCRYPTO_CERT_Cmp;
  }

  x509_b = CRYPTO_PEM2X509 (cert_b, tamCertB);
  if ( !x509_b ) {
    ret = 2;
    goto finCRYPTO_CERT_Cmp;
  }

  if ( X509_cmp(x509_a, x509_b) == 0 )
    ret = 0;
  else
    ret = 1;

finCRYPTO_CERT_Cmp:

  if ( x509_a ) {
    X509_free(x509_a);
    x509_a = NULL;
  }

  if ( x509_b ) {
    X509_free(x509_b);
    x509_b = NULL;
  }

  return ret;
}

/*! \brief Determina el key usage de un certificado.
 *
 * \param cert
 *        Certificado en formato pem
 *
 * \param tamCert
 *        El tamaño de cert
 * 
 * \param ex_kusage
 *        Este parámetro de salida se inicializará con
 *        varios flags dependiendo del key usage del
 *        certificado. Posteriormente se puede determinar
 *        haciendo un and bit a bit contra los siguientes
 *        valores: CRYPTO_KU_DIGITAL_SIGNATURE,
 *        CRYPTO_KU_NON_REPUDIATION,
 *	  CRYPTO_KU_KEY_ENCIPHERMENT,
 *        CRYPTO_KU_DATA_ENCIPHERMENT,
 *        CRYPTO_KU_KEY_AGREEMENT,
 *        CRYPTO_KU_KEY_CERT_SIGN,
 *        CRYPTO_KU_CRL_SIGN,
 *        CRYPTO_KU_ENCIPHER_ONLY,
 *        CRYPTO_KU_DECIPHER_ONLY
 *
 * \retval 1
 *         Error
 *
 * \retval 0
 *         Ok
 *
 */

int CRYPTO_X509_Get_KeyUsage (unsigned char *cert, unsigned long tamCert, unsigned long *ex_kusage)
{
  X509 *x509Cert = NULL;
  int ret = 0;
  ASN1_BIT_STRING *usage = NULL;

  if ( !ex_kusage ) {
    ret = 1;
    goto finCRYPTO_X509_Get_KeyUsage;
  }

  x509Cert = CRYPTO_PEM2X509 (cert, tamCert);

  if ( !x509Cert ) {
    ret = 1;
    goto finCRYPTO_X509_Get_KeyUsage;
  }

  *ex_kusage = 0;

  if((usage=X509_get_ext_d2i(x509Cert, NID_key_usage, NULL, NULL))) {

    if(usage->length > 0) {
      *ex_kusage = usage->data[0];
      if(usage->length > 1)
	*ex_kusage |= usage->data[1] << 8;
    } else 
      *ex_kusage = 0;

  }

finCRYPTO_X509_Get_KeyUsage:

  if ( x509Cert ) {
    X509_free(x509Cert);
    x509Cert = NULL;
  }

  if ( usage ) {
    ASN1_BIT_STRING_free(usage);
    usage = NULL;
  }

  return ret;

}

/*! \brief Determina si el Key usage del certificado especifica firma.
 *
 * Determina si el Key usage del certificado especifica firma. Esta función resulta
 * últil en la importación de key blobs. Para determinar si la llave será de tipo
 * AT_KEYEXCHANGE o AT_SIGNATURE.
 *
 * \todo Esta función está por acabar de implementar
 *
 * \param cert
 *        El certificado, en formato PEM.
 *
 * \param tamCert
 *        El tamaño en bytes del certificado
 *
 * \retval 0
 *         No es para firma.
 *
 * \retval 1
 *         Sí es para firma
 * 
 * \retval 2
 *         Error
 */

int CRYPTO_X509_Get_Purpose_Sign (unsigned char *cert, unsigned long tamCert)
{

  X509 *x509Cert = NULL;
  int ret = 0;
  ASN1_BIT_STRING *ku;
  int crit;

  if ( !cert ) {
    ret = 2;
    goto finCRYPTO_X509_Get_Purpose_Sign;
  }

  x509Cert = CRYPTO_PEM2X509 (cert, tamCert);


  if ( !x509Cert ) {
    ret = 2;
    goto finCRYPTO_X509_Get_Purpose_Sign;
  }

  ku = X509_get_ext_d2i(x509Cert, NID_key_usage, &crit, NULL);

  if ( !ku ) {
    ret = 0;
    goto finCRYPTO_X509_Get_Purpose_Sign;
  }


finCRYPTO_X509_Get_Purpose_Sign:

  if ( x509Cert ) {
    X509_free(x509Cert);
    x509Cert = NULL;
  }	

  return ret;

}

/*! \brief Detruye el contenido de un buffer.
 *  
 * Destruye el contenido de un buffer.
 *
 * \param buf
 *        El buffer cuyo contenido será destruído.
 *
 * \param size
 *        El tamaño del buffer a destruir
 *
 */
#ifndef WIN32
void CRYPTO_SecureZeroMemory ( void *buf, unsigned long size )
{


  volatile unsigned char *i_buf = (volatile unsigned char *) buf;

  while ( size-- ) {
    *i_buf = 0x55;
    *i_buf = 0xaa;
    *(i_buf++) = 0;
  }


}
#endif




/*! \brief Transforma un PRIVATEKEYBLOB de Microsoft Crypto API en una llave
 *         privada PEM
 *
 * Transforma un PRIVATEKEYBLOB de Microsoft Crypto API en una llave
 * privada PEM.
 *
 * \param blob
 *        [ENTADA] PRIVATEKEYBLOB de entrada
 *
 * \param tamBlob
 *        [ENTRADA] Tamaño de blob en bytes
 *
 * \param llave
 *        [SALIDA] Llave en formato PEM
 *
 * \param tamLlave
 *        [SALIDA] Tamaño de la llave en bytes
 *
 * \retval 0
 *         Error
 *
 * \retval 1
 *         Ok
 */

int CRYPTO_BLOB2LLAVE ( unsigned char *blob, unsigned long tamBlob,
	                    unsigned char *llave, unsigned long *tamLlave )
{
  RSA *pKey = NULL;
  RSAPUBKEY *rsaPubKey;
  BIO *bioMem = NULL;
  unsigned char *auxBlob = NULL;
  char *pp;
  long tampp;
  int ret = 0;

  if ( ! blob ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  if ( ! tamLlave ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  /* Hago una copia del blob de entrada para realizar los
   * cambios en el byte order de los campos (la BN espera
   * big endian y los blobs son little endian)
   */

  auxBlob = (unsigned char *) malloc ( tamBlob );
  if ( ! auxBlob ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  memcpy(auxBlob, blob, tamBlob);

  rsaPubKey  = (RSAPUBKEY *) (auxBlob + sizeof(BLOBHEADER));

  CRYPTO_ByteOrder((unsigned char *) &(rsaPubKey->pubexp), sizeof(DWORD));
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY), rsaPubKey->bitlen / 8 );
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen /8, rsaPubKey->bitlen/16);
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen /8 + rsaPubKey->bitlen/16, rsaPubKey->bitlen/16);
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen / 8 + 2*rsaPubKey->bitlen/16, rsaPubKey->bitlen/16);
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen / 8 + 3*rsaPubKey->bitlen/16, rsaPubKey->bitlen/16);
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen / 8 + 4*rsaPubKey->bitlen/16, rsaPubKey->bitlen/16);
  CRYPTO_ByteOrder( auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen / 8 + 5*rsaPubKey->bitlen/16, rsaPubKey->bitlen/8);

  /* Ahora construímos un objeto RSA
   */

  pKey = RSA_new();
  if ( ! pKey ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->n = BN_bin2bn(auxBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY), rsaPubKey->bitlen/8, NULL);
  if ( ! pKey->n ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }
 
  pKey->e = BN_bin2bn((unsigned char *) &(rsaPubKey->pubexp), sizeof(DWORD), NULL);
  if ( ! pKey->e ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->d = BN_bin2bn(auxBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+rsaPubKey->bitlen/8+5*rsaPubKey->bitlen/16, rsaPubKey->bitlen/8, NULL);
  if ( ! pKey->d ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->p = BN_bin2bn(auxBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+rsaPubKey->bitlen/8, rsaPubKey->bitlen/16, NULL);
  if ( ! pKey->p ) {
	ret = 1;
	goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->q = BN_bin2bn(auxBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+rsaPubKey->bitlen/8+rsaPubKey->bitlen/16, rsaPubKey->bitlen/16, NULL);
  if ( ! pKey->q ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->dmp1 = BN_bin2bn(auxBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+rsaPubKey->bitlen/8 + 2*rsaPubKey->bitlen/16, rsaPubKey->bitlen/16, NULL);
  if ( ! pKey->dmp1 ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->dmq1 = BN_bin2bn(auxBlob+sizeof(BLOBHEADER)+sizeof(RSAPUBKEY)+rsaPubKey->bitlen/8 + 3*rsaPubKey->bitlen/16, rsaPubKey->bitlen/16, NULL);
  if ( ! pKey->dmq1 ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  pKey->iqmp = BN_bin2bn(auxBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + rsaPubKey->bitlen/8 + 4*rsaPubKey->bitlen/16, rsaPubKey->bitlen/16, NULL);
  if ( ! pKey->iqmp ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  /* Y ahora vamos a por PEM
   */

  bioMem = BIO_new(BIO_s_mem());
  if ( ! bioMem ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }
  
  if ( ! PEM_write_bio_RSAPrivateKey(bioMem, pKey, 0, NULL, 0, NULL, 0) ) {
    ret = 1;
    goto finCRYPTO_BLOB2LLAVE;
  }

  tampp = BIO_get_mem_data(bioMem, &pp);
  
  if ( llave ) {
	  if ( *tamLlave < tampp ) {
		ret = 1;
		goto finCRYPTO_BLOB2LLAVE;
	  }

	  memcpy(llave, pp, tampp);
  } else
	  *tamLlave = tampp;

 finCRYPTO_BLOB2LLAVE:

  if ( pKey ) 
    RSA_free(pKey);
  
  if ( auxBlob ) {
    CRYPTO_SecureZeroMemory(auxBlob, tamBlob);
    free(auxBlob);
  }

  if ( bioMem ) 
    BIO_free(bioMem);

  return ret;

}






int CRYPTO_X509_DER2PEM ( unsigned char *derCert, unsigned long tamDER, 
						  unsigned char *pemCert, unsigned long *tamPEM )
{
	BIO *bioMem = NULL;
	X509 *cert = NULL;
	unsigned char *aux;
	int ret = 0;

	if ( ! derCert )
		return 1;
	if ( ! tamPEM )
		return 1;

	bioMem = BIO_new_mem_buf(derCert, tamDER);
	if ( ! bioMem ) {
		ret = 1;
		goto endCRYPTO_X509_DER2PEM;
	}

	cert = d2i_X509_bio(bioMem, NULL);
	if ( ! cert ) {
		ret = 1;
		goto endCRYPTO_X509_DER2PEM;
	}

	BIO_free(bioMem);
	bioMem = NULL;

	bioMem = BIO_new(BIO_s_mem());
	if ( ! bioMem ) {
		ret = 1;
		goto endCRYPTO_X509_DER2PEM;
	}

	if ( ! PEM_write_bio_X509(bioMem, cert) ) {
		ret = 1;
		goto endCRYPTO_X509_DER2PEM;
	}

	*tamPEM = BIO_get_mem_data(bioMem, &aux);

	if ( pemCert ) 
		memcpy(pemCert, aux, *tamPEM);
	
endCRYPTO_X509_DER2PEM:

	if ( bioMem ) 
		BIO_free(bioMem);
	
	if ( cert )	
		X509_free(cert);

	return ret;
}









int CRYPTO_X509_FingerPrint    ( unsigned char *certPEM, unsigned long tam, int mdAlg, unsigned char *fingerPrint )
{
	X509 *x = NULL;
	EVP_MD *md;
	unsigned int len;
	int ret = 0;

	if ( ! certPEM )
		return 1;
	if ( ! fingerPrint )
		return 1;
	switch ( mdAlg ) {
	case ALGID_SHA1:
		md = EVP_sha1();
		break;

	case ALGID_MD5:
		md = EVP_md5();
		break;
	default:
		return 1;
	}
	
	x = CRYPTO_PEM2X509(certPEM, tam);
	if ( ! x ) {
		ret = 1;
		goto endCRYPTO_X509_FingerPrint;
	}

	if ( ! X509_digest(x, md, fingerPrint, &len) ) {
		ret = 1;
		goto endCRYPTO_X509_FingerPrint;
	}

endCRYPTO_X509_FingerPrint:

	if ( x ) 
		X509_free(x);
	
	return ret;
}






int CRYPTO_X509_PEM2DER ( unsigned char *pemCert, unsigned long tamPEM, unsigned char *derCert, unsigned long *tamDER)
{
	X509 *x = NULL;
	unsigned char *aux = NULL;
	int ret = 0;

	if ( ! pemCert )
		return 1;
	if ( ! tamDER )
		return 1;

	x = CRYPTO_PEM2X509 (pemCert, tamPEM);
	if ( ! x ) {
		ret = 1;
		goto endCRYPTO_X509_PEM2DER;
	}

	*tamDER = (unsigned long ) i2d_X509(x, &aux);
	if ( ! *tamDER ) {
		ret = 1;
		goto endCRYPTO_X509_PEM2DER;
	}
	if ( ! derCert ) {
		ret = 0;
		goto endCRYPTO_X509_PEM2DER;
	}

	memcpy(derCert, aux, *tamDER);

endCRYPTO_X509_PEM2DER:

	if ( x )
		X509_free(x);
	if ( aux )
		OPENSSL_free(aux);

	return ret;
}

