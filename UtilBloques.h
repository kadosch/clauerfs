
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

#ifndef UTILBLOQUES_H
#define UTILBLOQUES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Tipos de bloques específicos */

#define BLOQUE_BLANCO			0x00
#define BLOQUE_LLAVE_PRIVADA	        0x01
#define BLOQUE_CERT_PROPIO		0x02
#define BLOQUE_CERT_WEB			0x03
#define BLOQUE_CERT_RAIZ		0x04
#define	BLOQUE_KNOWN_HOSTS		0x05
#define BLOQUE_KEY_CONTAINERS           0x06
#define BLOQUE_PRIVKEY_BLOB		0x07
#define BLOQUE_PUBKEY_BLOB		0x08
#define BLOQUE_CERT_OTROS		0x09
#define BLOQUE_CERT_INTERMEDIO          0x0a
#define BLOQUE_CIPHER_PRIVKEY_BLOB      0x0b
#define BLOQUE_CRYPTO_WALLET		0x0c
#define BLOQUE_CIPHER_PRIVKEY_PEM       0x0d
#define BLOQUE_CHANGE_PASSWORD		0x0e
#define BLOQUE_PUTTYKEY				0x0f


#define CERT_PROPIO		BLOQUE_CERT_PROPIO
#define CERT_WEB		BLOQUE_CERT_WEB
#define CERT_RAIZ		BLOQUE_CERT_RAIZ
#define LLAVE_PRIVADA   BLOQUE_LLAVE_PRIVADA
#define KNOWN_HOSTS		BLOQUE_KNOWN_HOSTS
#define PRIVKEY_BLOB	BLOQUE_PRIVKEY_BLOB
#define PUBKEY_BLOB		BLOQUE_PUBKEY_BLOB

/* Algunos defines adicionales */

#define TAM_KEY_CONTAINER	306     /* Tamaño de un key container en bytes */
#define NUM_KEY_CONTAINERS	33      /* Número total de key containers que caben en un bloque: (TAM_BLOQUE-8)/TAM_KEY_CONTAINER */
#define TAM_BLOQUE			10240   /* Tamaño de un bloque en bytes */

/* Utilidades para los bloques de BLOQUE_KEY_CONTAINERS */

#define BLOQUE_KeyContainer_SetOcupado(keyContainer)	 ( *(keyContainer) = *(keyContainer) | 0x01 )
#define BLOQUE_KeyContainer_UnsetOcupado(keyContainer)	 ( *(keyContainer) = *(keyContainer) & 0xFE )
#define BLOQUE_KeyContainer_GetOcupado(keyContainer)	 ( *(keyContainer) & 0x01 )

#define BLOQUE_KeyContainer_SetExchange(keyContainer)	 ( *(keyContainer) = *(keyContainer) | 0x02 )
#define BLOQUE_KeyContainer_UnsetExchange(keyContainer)	 ( *(keyContainer) = *(keyContainer) & 0xFD )
#define BLOQUE_KeyContainer_GetExchange(keyContainer)	 ( *(keyContainer) & 0x02 )

#define BLOQUE_KeyContainer_SetSignature(keyContainer)	 ( *(keyContainer) = *(keyContainer) | 0x04 )
#define BLOQUE_KeyContainer_UnsetSignature(keyContainer) ( *(keyContainer) = *(keyContainer) & 0xFB )
#define BLOQUE_KeyContainer_GetSignature(keyContainer)	 ( *(keyContainer) & 0x04 )

#define BLOQUE_KeyContainer_GetUnidadExchange(keyContainer)	    ( *((long *)((keyContainer)+1+257)))
#define BLOQUE_KeyContainer_GetUnidadSignature(keyContainer)	( *((long *)((keyContainer)+1+257+4)) )


/* Definiciones de tipos
 */

typedef struct INFO_KEY_CONTAINER {
  char *nombreKeyContainer;
  unsigned long EXCHANGE, SIGNATURE;
  int exportaEx, exportaSig;
  unsigned char idExchange[20];
  unsigned char idSignature[20];
} INFO_KEY_CONTAINER;

typedef unsigned char TIPO_BLOQUE;

/* Utilidades generales */
 
void BLOQUE_Set_Cifrado (unsigned char *bloque);
void BLOQUE_Set_Vacio   (unsigned char *bloque);
void BLOQUE_Set_Claro   (unsigned char *bloque);

int BLOQUE_Es_Cifrado  (unsigned char *bloque);
int BLOQUE_Es_Vacio    (unsigned char *bloque);
int BLOQUE_Es_Claro    (unsigned char *bloque);


#ifdef _DEBUG
char *BLOQUE_Estado_Str (unsigned char *bloque);
void BLOQUE_Print (unsigned char *bloque, FILE *fp);
#endif
char *BLOQUE_Tipo_Str	(unsigned char *bloque);

/* Utilidades para los bloques de tipo Key Container */

int    BLOQUE_KeyContainer_Insertar                ( unsigned char *bloque, const char *nombreKeyContainer );
void   BLOQUE_KeyContainer_Nuevo                   ( unsigned char *bloque );
int    BLOQUE_KeyContainer_Borrar                  ( unsigned char *bloque, const char *nombreKeyContainer );
int    BLOQUE_KeyContainer_EstablecerEXCHANGE      ( unsigned char *bloque, const char *nombreKeyContainer, long unidad, int exportable );
int    BLOQUE_KeyContainer_EstablecerSIGNATURE     ( unsigned char *bloque, const char *nombreKeyContainer, long unidad, int exportable );
int    BLOQUE_KeyContainer_Establecer_ID_Exchange  (unsigned char *bloque, const char *nombreKeyContainer, unsigned char id[20]);
int    BLOQUE_KeyContainer_Establecer_ID_Signature (unsigned char *bloque, const char *nombreKeyContainer, unsigned char id[20]);
int    BLOQUE_KeyContainer_Establecer_Export       ( unsigned char *bloque, const char *nombreKeyContainer, int signature, int exportable);
int    BLOQUE_KeyContainer_Enumerar                ( unsigned char *bloque, INFO_KEY_CONTAINER *lstContainers, unsigned int *tamLstContainers );
unsigned char * BLOQUE_KeyContainer_Buscar         ( unsigned char *bloque, const char *nombreKeyContainer );
int    BLOQUE_KeyContainer_Vacio                   ( unsigned char *bloque );
void   BLOQUE_KeyContainer_Print                   (  unsigned char *bloque, int flags, FILE *fp );

unsigned char * BLOQUE_KeyContainer_Get_ID_Exchange  ( unsigned char *bloque, const char *nombreKeyContainer);
unsigned char * BLOQUE_KeyContainer_Get_ID_Signature ( unsigned char *bloque, const char *nombreKeyContainer);

/* Utilidades para los bloques de tipo BLOQUE_LLAVE_PRIVADA */

void            BLOQUE_LLAVEPRIVADA_Nuevo      ( unsigned char *bloque );
unsigned long   BLOQUE_LLAVEPRIVADA_Get_Tam    ( unsigned char *bloque );
unsigned char * BLOQUE_LLAVEPRIVADA_Get_Id     ( unsigned char *bloque );
unsigned char * BLOQUE_LLAVEPRIVADA_Get_Objeto ( unsigned char *bloque );
void            BLOQUE_LLAVEPRIVADA_Set_Tam    ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_LLAVEPRIVADA_Set_Id     ( unsigned char *bloque, unsigned char id[20] );
void            BLOQUE_LLAVEPRIVADA_Set_Objeto ( unsigned char *bloque, unsigned char *llave, unsigned long tam );


/* Utilidades para los bloques de tipo BLOQUE_CIPHER_PRIVKEY_PEM */ 

void            BLOQUE_CIPHER_PRIVKEY_PEM_Nuevo      ( unsigned char *bloque );
unsigned long   BLOQUE_CIPHER_PRIVKEY_PEM_Get_Tam    ( unsigned char *bloque );
unsigned char * BLOQUE_CIPHER_PRIVKEY_PEM_Get_String_Id (unsigned char *bloque, unsigned char *str_id );
unsigned char * BLOQUE_CIPHER_PRIVKEY_PEM_Get_Id     ( unsigned char *bloque );
unsigned char * BLOQUE_CIPHER_PRIVKEY_PEM_Get_Objeto ( unsigned char *bloque );
void            BLOQUE_CIPHER_PRIVKEY_PEM_Set_Tam    ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_CIPHER_PRIVKEY_PEM_Set_Id     ( unsigned char *bloque, unsigned char id[20] );
void            BLOQUE_CIPHER_PRIVKEY_PEM_Set_Objeto ( unsigned char *bloque, unsigned char *llave, unsigned long tam );




/* Utilidades para los bloques de tipo BLOQUE_CERT_PROPIO */

void            BLOQUE_CERTPROPIO_Nuevo		   ( unsigned char *bloque );
unsigned long   BLOQUE_CERTPROPIO_Get_Tam	   ( unsigned char *bloque );
unsigned char * BLOQUE_CERTPROPIO_Get_Id	   ( unsigned char *bloque );
unsigned char * BLOQUE_CERTPROPIO_Get_Objeto	   ( unsigned char *bloque );
void            BLOQUE_CERTPROPIO_Set_Tam	   ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_CERTPROPIO_Set_Id	   ( unsigned char *bloque, unsigned char id[20] );
void            BLOQUE_CERTPROPIO_Set_Objeto	   ( unsigned char *bloque, unsigned char *cert, unsigned long tam );
char *          BLOQUE_CERTPROPIO_Get_FriendlyName ( unsigned char *bloque );
void		BLOQUE_CERTPROPIO_Set_FriendlyName ( unsigned char *bloque, char *friendlyName );



/* Utilidades para los bloques de tipo BLOQUE_PUTTYKEY */

void            BLOQUE_PUTTYKEY_Nuevo      ( unsigned char *bloque );
unsigned long   BLOQUE_PUTTYKEY_Get_Tam    ( unsigned char *bloque );
unsigned char * BLOQUE_PUTTYKEY_Get_Objeto ( unsigned char *bloque );
void            BLOQUE_PUTTYKEY_Set_Tam    ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_PUTTYKEY_Set_Objeto ( unsigned char *bloque, unsigned char *llave, unsigned long tam );




/* Utilidades para los bloques de tipo BLOQUE_CERT_RAIZ */

void            BLOQUE_CERTRAIZ_Nuevo            ( unsigned char *bloque );
unsigned long   BLOQUE_CERTRAIZ_Get_Tam		   ( unsigned char *bloque );
unsigned char * BLOQUE_CERTRAIZ_Get_Objeto	   ( unsigned char *bloque );
void            BLOQUE_CERTRAIZ_Set_Tam		   ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_CERTRAIZ_Set_Objeto	   ( unsigned char *bloque, unsigned char *cert, unsigned long tam );

char *	        BLOQUE_CERTRAIZ_Get_FriendlyName ( unsigned char *bloque );
void		BLOQUE_CERTRAIZ_Set_FriendlyName ( unsigned char *bloque, char *friendlyName );

/* Utilidades para los bloques de tipo BLOQUE_PRIVKEY_BLOB */

void            BLOQUE_PRIVKEYBLOB_Nuevo      ( unsigned char *bloque );
unsigned long   BLOQUE_PRIVKEYBLOB_Get_Tam    ( unsigned char *bloque );
unsigned char * BLOQUE_PRIVKEYBLOB_Get_Id     ( unsigned char *bloque );
unsigned char * BLOQUE_PRIVKEYBLOB_Get_Objeto ( unsigned char *bloque );
void            BLOQUE_PRIVKEYBLOB_Set_Tam    ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_PRIVKEYBLOB_Set_Id     ( unsigned char *bloque, unsigned char id[20] );
void            BLOQUE_PRIVKEYBLOB_Set_Objeto ( unsigned char *bloque, unsigned char *blob, unsigned long tam );

/* Utilidades para los bloques de tipo BLOQUE_PRIVKEY_BLOB */

void            BLOQUE_CIPHPRIVKEYBLOB_Nuevo         ( unsigned char *bloque );
unsigned long   BLOQUE_CIPHPRIVKEYBLOB_Get_Tam       ( unsigned char *bloque );
unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Id        ( unsigned char *bloque );
unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Objeto    ( unsigned char *bloque );
unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Salt      ( unsigned char *bloque );
unsigned long   BLOQUE_CIPHPRIVKEYBLOB_Get_IterCount ( unsigned char *bloque );
unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Iv        ( unsigned char *bloque );
char *          BLOQUE_CIPHPRIVKEYBLOB_Get_Desc      ( unsigned char *bloque );

void            BLOQUE_CIPHPRIVKEYBLOB_Set_Tam       ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_CIPHPRIVKEYBLOB_Set_Id        ( unsigned char *bloque, unsigned char id[20] );
void            BLOQUE_CIPHPRIVKEYBLOB_Set_Objeto    ( unsigned char *bloque, unsigned char *blob, unsigned long tam );
void            BLOQUE_CIPHPRIVKEYBLOB_Set_IterCount ( unsigned char *bloque, unsigned long iterCount );
void            BLOQUE_CIPHPRIVKEYBLOB_Set_Salt      ( unsigned char *bloque, unsigned char salt[20] );
void			BLOQUE_CIPHPRIVKEYBLOB_Set_Iv        ( unsigned char *bloque, unsigned char iv[20] );
void            BLOQUE_CIPHPRIVKEYBLOB_Set_Desc      ( unsigned char *bloque, char ascii_desc[31] );

/* Utilidades para los bloques de tipo BLOQUE_PUBKEY_BLOB */

void            BLOQUE_PUBKEYBLOB_Nuevo      ( unsigned char *bloque );
unsigned long   BLOQUE_PUBKEYBLOB_Get_Tam    ( unsigned char *bloque );
unsigned char * BLOQUE_PUBKEYBLOB_Get_Id     ( unsigned char *bloque );
unsigned char * BLOQUE_PUBKEYBLOB_Get_Objeto ( unsigned char *bloque );
void            BLOQUE_PUBKEYBLOB_Set_Tam    ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_PUBKEYBLOB_Set_Id     ( unsigned char *bloque, unsigned char id[20] );
void            BLOQUE_PUBKEYBLOB_Set_Objeto ( unsigned char *bloque, unsigned char *blob, unsigned long tam );

/* Utilidades para los bloques de tipo BLOQUE_CERT_OTROS */

void            BLOQUE_CERTOTROS_Nuevo		  ( unsigned char *bloque );
unsigned long   BLOQUE_CERTOTROS_Get_Tam	  ( unsigned char *bloque );
unsigned char * BLOQUE_CERTOTROS_Get_Objeto	  ( unsigned char *bloque );
void            BLOQUE_CERTOTROS_Set_Tam	  ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_CERTOTROS_Set_Objeto	  ( unsigned char *bloque, unsigned char *cert, unsigned long tam );
char *		    BLOQUE_CERTOTROS_Get_FriendlyName ( unsigned char *bloque );
void		    BLOQUE_CERTOTROS_Set_FriendlyName ( unsigned char *bloque, char *friendlyName );

/* Utilidades para los bloques de tipo BLOQUE_CERT_INTERMEDIO */

void            BLOQUE_CERTINTERMEDIO_Nuevo            ( unsigned char *bloque );
unsigned long   BLOQUE_CERTINTERMEDIO_Get_Tam	       ( unsigned char *bloque );
unsigned char * BLOQUE_CERTINTERMEDIO_Get_Objeto       ( unsigned char *bloque );
void            BLOQUE_CERTINTERMEDIO_Set_Tam	       ( unsigned char *bloque, unsigned long tam );
void            BLOQUE_CERTINTERMEDIO_Set_Objeto       ( unsigned char *bloque, unsigned char *cert, unsigned long tam );
char *	        BLOQUE_CERTINTERMEDIO_Get_FriendlyName ( unsigned char *bloque );
void	        BLOQUE_CERTINTERMEDIO_Set_FriendlyName ( unsigned char *bloque, char *friendlyName );

/* Códigos de error */

#define ERR_BLOQUE_NO                   0
#define ERR_BLOQUE_SI                   1
#define ERR_BLOQUE_CONTAINER_EXISTE     2
#define ERR_BLOQUE_SIN_ESPACIO          3
#define ERR_BLOQUE_NO_ENCONTRADO        4

#ifdef __cplusplus
}
#endif

#endif

