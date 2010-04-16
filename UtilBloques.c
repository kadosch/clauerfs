
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

#include "UtilBloques.h"

#include <time.h>
#include <stdio.h>

#define BYTES_ID			20
#define BYTES_TAMANYO			4
#define BYTES_CABECERA			8
#define BYTES_FRIENDLY_NAME		31
#define BYTES_TIPO			1



unsigned char * BLOQUE_KeyContainer_Get_ID_Exchange  ( unsigned char *bloque, const char *nombreKeyContainer)
{
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return NULL;

    return keyContainer+1+257+8;

}


unsigned char * BLOQUE_KeyContainer_Get_ID_Signature ( unsigned char *bloque, const char *nombreKeyContainer)
{
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return NULL;

    return keyContainer+1+257+8+20;
}




int BLOQUE_KeyContainer_Establecer_ID_Exchange (unsigned char *bloque, const char *nombreKeyContainer, unsigned char id[20])
{
    long *aux2 = NULL;
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return ERR_BLOQUE_NO_ENCONTRADO;

    memcpy(keyContainer+1+257+8, id, 20);

    return ERR_BLOQUE_NO;
}




int BLOQUE_KeyContainer_Establecer_ID_Signature (unsigned char *bloque, const char *nombreKeyContainer, unsigned char id[20])
{

    long *aux2 = NULL;
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return ERR_BLOQUE_NO_ENCONTRADO;

    memcpy(keyContainer+1+257+8+20, id, 20);

    return ERR_BLOQUE_NO;
}





#ifdef _DEBUG

char *BLOQUE_Estado_Str (unsigned char *bloque)
{

    if ( BLOQUE_Es_Cifrado(bloque) ) 
	return "Cifrado";
    else if ( BLOQUE_Es_Vacio(bloque) )
	return "Vacío";
    else if ( BLOQUE_Es_Claro(bloque) )
	return "Claro";
    else
	return "Desconocido";

}


void BLOQUE_Print (unsigned char *bloque, FILE *fp)
{

    int i;
    unsigned char *id;

    if ( *(bloque+1) == BLOQUE_KEY_CONTAINERS ) {
	BLOQUE_KeyContainer_Print ( bloque, 1, fp );
    } else if ( *(bloque+1) == BLOQUE_LLAVE_PRIVADA ) {
	id = BLOQUE_LLAVEPRIVADA_Get_Id (bloque);
	for ( i = 0 ; i < 20 ; i++ )
	    fprintf(fp, "%02x ", *(id+i));
	fprintf(fp, "\r\n");
    } else if ( *(bloque+1) == BLOQUE_PRIVKEY_BLOB ) {
	id = BLOQUE_PRIVKEYBLOB_Get_Id (bloque);
	for ( i = 0 ; i < 20 ; i++ )
	    fprintf(fp, "%02x ", *(id+i));
	fprintf(fp, "\r\n");
    }



}



#endif

char *BLOQUE_Tipo_Str	(unsigned char *bloque)
{

    switch (*(bloque+1)) {

	case BLOQUE_BLANCO:
	    return "BLANCO";
	case BLOQUE_LLAVE_PRIVADA:
	    return "LLAVE_PRIVADA";
	case BLOQUE_CERT_PROPIO:
	    return "CERT_PROPIO";
	case BLOQUE_CERT_WEB:
	    return "CERT_WEB";
	case BLOQUE_CERT_RAIZ:
	    return "CERT_RAIZ";
	case BLOQUE_KNOWN_HOSTS:
	    return "KNOWN_HOSTS";
	case BLOQUE_KEY_CONTAINERS:
	    return "KEY_CONTAINERS";
	case BLOQUE_PRIVKEY_BLOB:
	    return "PRIVKEY_BLOB";
	case BLOQUE_PUBKEY_BLOB:
	    return "PUBKEY_BLOB";
	case BLOQUE_CERT_OTROS:
	    return "CERT_OTROS";
	case BLOQUE_CERT_INTERMEDIO:
	    return "CERT_CERT_INTERMEDIO";
	default:
	    return "DESCONOCIDO";
    }

}



/*! \brief Establece el tipo de primer nivel del bloque a cifrado
 * 
 * Establece el tipo de primer nivel del bloque a cifrado.
 *
 * \param bloque
 *        ENTRADA/SALIDA. El bloque de TAM_BLOQUE bytes
 *
 */

void BLOQUE_Set_Cifrado (unsigned char *bloque)
{
    srand((unsigned int)time(NULL));
    *bloque = (rand() % 85) + 170;
}


/*! \brief Establece el tipo de primer nivel del bloque a vacío
 * 
 * Establece el tipo de primer nivel del bloque a vacío.
 *
 * \param bloque
 *        ENTRADA/SALIDA. El bloque de TAM_BLOQUE bytes
 *
 */

void BLOQUE_Set_Vacio (unsigned char *bloque)
{
    srand((unsigned int)time(NULL));
    *bloque = (rand() % 85) + 0;
}


/*! \brief Establece el tipo de primer nivel del bloque a claro
 * 
 * Establece el tipo de primer nivel del bloque a claro.
 *
 * \param bloque
 *        ENTRADA/SALIDA. El bloque de TAM_BLOQUE bytes
 *
 */

void BLOQUE_Set_Claro (unsigned char *bloque)
{
    srand((unsigned int)time(NULL));
    *bloque = (rand() % 85) + 85;
}


/*! \brief Determina si bloque es de tipo cifrado o no
 *
 * Determina si bloque es de tipo cifrado o no.
 *
 * \param bloque
 *        ENTRADA/SALIDA. El bloque de TAM_BLOQUE bytes
 *
 * \retval 1
 *		   El bloque es de tipo cifrado
 *
 * \retval 0
 *         El bloque no es de tipo cifrado
 */

int BLOQUE_Es_Cifrado (unsigned char *bloque)
{
    return ((*bloque >= 170) && (*bloque <= 254));
}


/*! \brief Determina si bloque es de tipo vacío o no
 *
 * Determina si bloque es de tipo vacío o no.
 *
 * \param bloque
 *        ENTRADA/SALIDA. El bloque de TAM_BLOQUE bytes
 *
 * \retval 1
 *		   El bloque es de tipo vacío
 *
 * \retval 0
 *         El bloque no es de tipo vacío
 */

int BLOQUE_Es_Vacio (unsigned char *bloque)
{
    return /* ((*bloque >= 0) && // It is an unsigned char can't be less than 0 */ ( *bloque <= 84 );
}

/*! \brief Determina si bloque es de tipo claro o no
 *
 * Determina si bloque es de tipo claro o no.
 *
 * \param bloque
 *        ENTRADA/SALIDA. El bloque de TAM_BLOQUE bytes
 *
 * \retval 1
 *		   El bloque es de tipo claro
 *
 * \retval 0
 *         El bloque no es de tipo claro
 */

int BLOQUE_Es_Claro (unsigned char *bloque)
{
    return ((*bloque >= 85) && ( *bloque <= 169) );
}


/*!
 * \brief Inserta un nuevo key container en el bloque indicado.
 *
 * Inserta un nuevo key container en el bloque indicado. Si el nombre del key container es
 * mayor que 256 se trunca a ese tamaño.
 *
 * \param bloque
 *		  ENTRADA/SALIDA. El bloque de tipo key container donde se va a insertar el nuevo key container
 *
 * \param nombreKeyContainer
 *		  ENTRADA. El nombre de key container como una cadena ASCII de 256 caracteres máximo
 *
 * \retval ERR_SIN_ESPACIO
 *		   No hay espacio disponible para insertar el nuevo key container.
 *
 * \retval ERR_CONTAINER_EXISTE
 *		   Se intenta insertar un key container que ya existe
 *
 * \retval ERR_NO
 *		   La función se ha ejecutado con éxito.
 *
 * \retval ERR_SI
 *		   Error indefinido
 *
 * \remarks Si el nombre del key container es mayor que 256 se trunca a ese tamaño.
 *
 */

int BLOQUE_KeyContainer_Insertar ( unsigned char *bloque,  const char *nombreKeyContainer)
{
    int numKeyContainers = 1;
    unsigned long aux = 0xffffffff;
    unsigned char *keyContainer = NULL;
    size_t tamNombre;

    if ( BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer) )
	return ERR_BLOQUE_CONTAINER_EXISTE;

    /*
     * Buscamos la posición del primer key container libre
     */

    keyContainer = bloque + 8;

    while ( BLOQUE_KeyContainer_GetOcupado(keyContainer) && (numKeyContainers <= NUM_KEY_CONTAINERS) ) {
	keyContainer += TAM_KEY_CONTAINER;
	++numKeyContainers;
    }

    if ( numKeyContainers > NUM_KEY_CONTAINERS )
	return ERR_BLOQUE_SIN_ESPACIO;

    /*
     * Ahora realizamos la inserción. Por defecto las llaves no son exportables
     */

    BLOQUE_KeyContainer_SetOcupado(keyContainer);
    BLOQUE_KeyContainer_UnsetExchange(keyContainer);
    BLOQUE_KeyContainer_UnsetSignature(keyContainer);

    tamNombre = strlen(nombreKeyContainer);
    tamNombre = ( tamNombre > 256 ) ? 256 : tamNombre;

    strncpy((char *)keyContainer+1,nombreKeyContainer, tamNombre);
    *(keyContainer+1+tamNombre) = '\0';

    *((long *)(keyContainer+1+257)) = -1;
    *((long *)(keyContainer+1+257+4)) = -1;

    return ERR_BLOQUE_NO;
}



/* \brief Crea un nuevo bloque de tipo key container
 *
 * Crea un nuevo bloque de tipo key container
 *
 * \param bloque
 *		  ENTRADA/SALIDA. Marca el bloque de tipo key container.
 *
 */

void BLOQUE_KeyContainer_Nuevo ( unsigned char *bloque)
{
    memset((void *)(bloque+8), 0, TAM_BLOQUE-8);
    *(bloque+1) = BLOQUE_KEY_CONTAINERS;
}


/*! \brief Borra un key container del bloque.
 *
 * Borra un key container del bloque
 *
 * \param bloque
 *		  ENTRADA/SALIDA. El bloque de tipo key container
 *
 * \param nombreKeyContainer
 *		  ENTRADA. El nombre del key container a borrar. Cadena ASCII de a lo sumo 256 caracteres.
 *
 * \retval ERR_NO_ENCONTRADO
 *		   No se encontró el key container.
 *
 */

int BLOQUE_KeyContainer_Borrar ( unsigned char *bloque,  const char *nombreKeyContainer)
{

    int encontrado = 0;
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return ERR_BLOQUE_NO_ENCONTRADO;

    memset((void *) keyContainer,0,TAM_KEY_CONTAINER);

    return ERR_BLOQUE_NO;
}

/*!
 * \brief Busca un key container dentro de un bloque de tipo key Container
 *
 * Busca un key container dentro de un bloque de tipo key Container
 *
 * \param bloque
 *		  ENTRADA. Bloque de tipo Key Container sobre el que realizaremos la búsqueda.
 *
 * \param nombreKeyContainer
 *		  ENTRADA. Nombre del key container que queremos buscar.
 *
 * \retval NULL
 *		   Key Container no encontrado
 *
 * \retval !NULL
 *		   Puntero al key container encontrado
 *
 */

unsigned char *BLOQUE_KeyContainer_Buscar ( unsigned char *bloque,  const char *nombreKeyContainer)
{
    int i;
    int encontrado = 0;
    unsigned char *keyContainer = NULL;

    if ( strlen(nombreKeyContainer) > 256 )
	return NULL;

    keyContainer = bloque + BYTES_CABECERA;

    for ( i = 0 ; !encontrado && (i < NUM_KEY_CONTAINERS) ; i++ ) {
	if ( BLOQUE_KeyContainer_GetOcupado(keyContainer) ) {

	    if ( strcmp((char *)keyContainer+1,nombreKeyContainer) == 0 ) {
		encontrado = 1;
	    }
	}
	keyContainer += TAM_KEY_CONTAINER;
    }

    if ( !encontrado )
	keyContainer = NULL;
    else
	keyContainer -= TAM_KEY_CONTAINER;

    return keyContainer;
}

/*!
 * \brief Establece la unidad donde se almacena la llave privada de tipo AT_EXCHANGE.
 *
 * \param bloque
 *		  ENTRADA/SALIDA. El bloque de tipo KeyContainer que vamos a modificar.
 *
 * \param nombreKeyContainer
 *		  ENTRADA. El nombre del key container con la llave de tipo AT_EXCHANGE
 *
 * \param unidad
 *		  ENTRADA. La unidad donde reside la llave privada.
 *
 * \param exportable
 *		  ENTRADA. Indica si la llave es o no exportable.
 *
 * \retval ERR_NO_ENCONTRADO
 *		   No se encontró el key container.
 *
 * \retval ERR_NO
 *		   La función se ejecutó correctamente.
 *
 * \todo PROBAR
 */

int BLOQUE_KeyContainer_EstablecerEXCHANGE (  unsigned char *bloque,
	const char *nombreKeyContainer,
	long unidad,
	int exportable )
{
    long *aux2 = NULL;
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return ERR_BLOQUE_NO_ENCONTRADO;

    aux2  = (long *) (keyContainer+1+257);
    *aux2 = unidad;

    ( exportable ) ? BLOQUE_KeyContainer_SetExchange(keyContainer) : BLOQUE_KeyContainer_UnsetExchange(keyContainer);

    return ERR_BLOQUE_NO;

}





/*!
 * \brief Borra un key container del bloque.
 *
 * Borra un key container del bloque. El borrado consiste simplemente en establecer el bit de ocupado a cero.
 *
 * \param bloque
 *		  ENTADA/SALIDA. El bloque de tipo key container que vamos a modificar.
 *
 * \param nombreKeyContainer
 *		  ENTRADA. El nombre del key container para el que vamos a establecer la llave de tipo AT_SIGNATURE.
 *
 * \param unidad
 *		  ENTRADA. El bloque en el que está el bloque de tipo PRIVKEYBLOB con la llave de tipo AT_SIGNATURE.
 *
 * \param exportable
 *		  ENTRADA. Indica si la llave es o no exportable.
 *
 * \retval ERR_NO_ENCONTRADO
 *		   No se encontró el key container.
 *
 */

int BLOQUE_KeyContainer_EstablecerSIGNATURE ( unsigned char *bloque,
	const char *nombreKeyContainer,
	long unidad,
	int exportable )
{
    long *aux2 = NULL;
    unsigned char *keyContainer = NULL;

    keyContainer = BLOQUE_KeyContainer_Buscar(bloque,nombreKeyContainer);

    if ( !keyContainer )
	return ERR_BLOQUE_NO_ENCONTRADO;

    aux2  = (long *) (keyContainer+1+257+4);
    *aux2 = unidad;

    ( exportable ) ? BLOQUE_KeyContainer_SetSignature(keyContainer) : BLOQUE_KeyContainer_UnsetExchange(keyContainer);

    return ERR_BLOQUE_NO;

}

/*!
 * \brief Enumera los key containers del bloque
 *
 * Enumera los key containers del bloque.
 *
 * \param bloque
 *		  ENTRADA. El bloque de tipo key containers.
 *
 * \param lstContainers
 *		  SALIDA. La lista de key containers.
 *
 * \param tamLstContainers
 *		  SALIDA. El tamaño de la lista de key containers devuelta.
 *
 * \retval ERR_NO_ENCONTRADO
 *		   No se encontró el key container.
 *
 * \retval ERR_NO
 *		   La funcion se ejecutó correctamente.
 *
 */

int BLOQUE_KeyContainer_Enumerar (  unsigned char *bloque,
	INFO_KEY_CONTAINER *lstContainers,
	unsigned int *tamLstContainers )
{
    unsigned char *keyContainer = NULL;
    unsigned int numKeyContainers = 0;
    unsigned int i,j;

    keyContainer = bloque + 8;

    /*
     * Determino el número de key containers presentes
     */

    for ( i = 0 ; i < NUM_KEY_CONTAINERS ; i++ ) {
	if ( BLOQUE_KeyContainer_GetOcupado(keyContainer) )
	    ++numKeyContainers;

	keyContainer += TAM_KEY_CONTAINER;
    }

    *tamLstContainers = numKeyContainers;

    if ( !lstContainers )
	return ERR_BLOQUE_NO;

    /*
     * Ahora rellenamos la estructura de datos. Se asume que
     * ya tiene suficiente memoria reservada.
     */

    keyContainer = bloque + 8;
    j = 0;
    for ( i = 0 ; i < NUM_KEY_CONTAINERS; i++ ) {

	if ( BLOQUE_KeyContainer_GetOcupado(keyContainer) ) {
	    lstContainers[j].exportaEx = BLOQUE_KeyContainer_GetExchange(keyContainer);
	    lstContainers[j].exportaSig = BLOQUE_KeyContainer_GetSignature(keyContainer);
	    lstContainers[j].nombreKeyContainer = (char *) malloc (strlen((char *)keyContainer+1)+1);
	    strcpy(lstContainers[j].nombreKeyContainer,(char *)keyContainer+1);
	    lstContainers[j].EXCHANGE = BLOQUE_KeyContainer_GetUnidadExchange(keyContainer);
	    lstContainers[j].SIGNATURE = BLOQUE_KeyContainer_GetUnidadSignature(keyContainer);
	    memcpy(lstContainers[j].idSignature, keyContainer+1+257+8+20,20);
	    memcpy(lstContainers[j].idExchange, keyContainer+1+257+8,20);

	    ++j;
	}

	keyContainer += TAM_KEY_CONTAINER;
    }

    return ERR_BLOQUE_NO;

}






#ifdef _DEBUG

void BLOQUE_KeyContainer_Print2 (  INFO_KEY_CONTAINER *lstContainers,
	unsigned int tamLstContainers )
{
    unsigned int i = 0,j;

    while ( i < tamLstContainers ) {

	printf("Nombre: %s\r\n", lstContainers[i].nombreKeyContainer);
	printf("\tExporta Exchange: %d\r\n", lstContainers[i].exportaEx);
	printf("\tExporta Signature: %d\r\n", lstContainers[i].exportaSig);
	printf("\tUnidad Exchange: %d\r\n", lstContainers[i].EXCHANGE);
	printf("\tUnidad Signature: %d\r\n", lstContainers[i].SIGNATURE);
	printf("\tID Exchange: ");
	for ( j= 0 ; j < 20 ; j++ ) {
	    printf("%02x", lstContainers[i].idExchange[j]);
	}
	printf("\r\n\tID Signature: ");
	for ( j = 0 ; j < 20 ; j++ ) {
	    printf("%02x", lstContainers[i].idSignature[j]);
	}
	printf("\r\n");
	++i;

    }

}



void BLOQUE_KeyContainer_Print (  unsigned char *bloque,  int flags,  FILE *fp )
{
    unsigned char *keyContainer = NULL;
    int numKeyContainers = 1;
    int j;

    keyContainer = bloque + BYTES_CABECERA;
    while ( numKeyContainers <= NUM_KEY_CONTAINERS ) {

	if ( BLOQUE_KeyContainer_GetOcupado(keyContainer) ) {
	    fprintf(fp,"Key Container: %s\r\n", keyContainer+1);
	    if ( flags ) {
		fprintf(fp,"\tBit de Ocupado: %d\r\n", (BLOQUE_KeyContainer_GetOcupado(keyContainer))? 1:0);
		fprintf(fp, "\tBit de Exchange: %d\r\n", (BLOQUE_KeyContainer_GetExchange(keyContainer))? 1:0);
		fprintf(fp, "\tBit de Signature: %d\r\n", (BLOQUE_KeyContainer_GetSignature(keyContainer))? 1:0);
		fprintf(fp, "\tUnidad Exchange: %ld\r\n", BLOQUE_KeyContainer_GetUnidadExchange(keyContainer));
		fprintf(fp, "\tUnidad Signature: %ld\r\n", BLOQUE_KeyContainer_GetUnidadSignature(keyContainer));
		fprintf(fp, "\tID Exchange: ");
		for ( j = 0 ; j < 20 ; j++ ) {
		    fprintf(fp, "%x ", *(keyContainer+1+257+8+j));
		}
		fprintf(fp, "\r\n\tID Signature: ");
		for ( j = 0 ; j < 20 ; j++ ) {
		    fprintf(fp, "%x ", *(keyContainer+1+257+8+20+j));
		}
		fprintf(fp, "\r\n");
	    }
	}

	keyContainer += TAM_KEY_CONTAINER;
	++numKeyContainers;
    }
}



#endif



int BLOQUE_KeyContainer_Vacio ( unsigned char *bloque)
{
    unsigned char *kc;
    int vacio = 0;
    int i = 0;

    kc = bloque + 8;
    while (vacio && ( i < NUM_KEY_CONTAINERS))
	if ( BLOQUE_KeyContainer_GetOcupado(kc) )
	    vacio = 1;
	else
	    kc+=TAM_KEY_CONTAINER;

    return vacio;
}



/*****************************************************************************************************
 * Utilidades para bloques de tipo BLOQUE_LLAVE_PRIVADA
 */


void BLOQUE_LLAVEPRIVADA_Nuevo (unsigned char *bloque) 
{
    *(bloque+1) = BLOQUE_LLAVE_PRIVADA;
}


unsigned long BLOQUE_LLAVEPRIVADA_Get_Tam(unsigned char *bloque)
{
    return *((unsigned long *)((bloque)+8+1));
}


unsigned char * BLOQUE_LLAVEPRIVADA_Get_Id (unsigned char *bloque)
{
    return bloque+8+5;
}


unsigned char * BLOQUE_LLAVEPRIVADA_Get_Objeto (unsigned char *bloque)
{
    return bloque+8+25;
}

void BLOQUE_LLAVEPRIVADA_Set_Tam (unsigned char *bloque, unsigned long tam) {
    *((unsigned long *)((bloque)+8+1)) = tam;
}

void BLOQUE_LLAVEPRIVADA_Set_Id(unsigned char *bloque, unsigned char id[20])
{
    memcpy(BLOQUE_LLAVEPRIVADA_Get_Id(bloque),id,20);
}


void BLOQUE_LLAVEPRIVADA_Set_Objeto(unsigned char *bloque, unsigned char *llave, unsigned long tam)
{
    memcpy(BLOQUE_LLAVEPRIVADA_Get_Objeto(bloque),llave,tam);
    BLOQUE_LLAVEPRIVADA_Set_Tam(bloque,tam);
}



/* Utilidades para los bloques de tipo BLOQUE_CIPHER */

unsigned char *  BLOQUE_CIPHER_PRIVKEY_PEM_Get_String_Id(unsigned char *bloque, unsigned char *str_id )
{
	unsigned char * id;
	int i;

    id= BLOQUE_CIPHER_PRIVKEY_PEM_Get_Id(bloque);
	for ( i=0 ; i<20 ; i++  ){
		snprintf( str_id+(2*i), 40-(2*i), "%02x", id[i] );
	}
	str_id[40]= '\0';
	return str_id;
}


void BLOQUE_CIPHER_PRIVKEY_PEM_Nuevo (unsigned char *bloque) 
{
    *(bloque+1) = BLOQUE_CIPHER_PRIVKEY_PEM;
}


unsigned long BLOQUE_CIPHER_PRIVKEY_PEM_Get_Tam(unsigned char *bloque)
{
    return *((unsigned long *)((bloque)+8+1));
}


unsigned char * BLOQUE_CIPHER_PRIVKEY_PEM_Get_Id (unsigned char *bloque)
{
    return bloque+8+5;
}


unsigned char * BLOQUE_CIPHER_PRIVKEY_PEM_Get_Objeto (unsigned char *bloque)
{
    return bloque+8+25;
}

void BLOQUE_CIPHER_PRIVKEY_PEM_Set_Tam (unsigned char *bloque, unsigned long tam) {
    *((unsigned long *)((bloque)+8+1)) = tam;
}

void BLOQUE_CIPHER_PRIVKEY_PEM_Set_Id(unsigned char *bloque, unsigned char id[20])
{
    memcpy(BLOQUE_LLAVEPRIVADA_Get_Id(bloque),id,20);
}


void BLOQUE_CIPHER_PRIVKEY_PEM_Set_Objeto(unsigned char *bloque, unsigned char *llave, unsigned long tam)
{
    memcpy(BLOQUE_CIPHER_PRIVKEY_PEM_Get_Objeto(bloque),llave,tam);
    BLOQUE_CIPHER_PRIVKEY_PEM_Set_Tam(bloque,tam);
}



/*****************************************************/



/* Utilidades para los bloques de tipo BLOQUE_CERT_PROPIO */


void BLOQUE_CERTPROPIO_Nuevo (unsigned char *bloque) 
{
    *(bloque + BYTES_TIPO) = BLOQUE_CERT_PROPIO;
    *(bloque + BYTES_CABECERA + BYTES_TAMANYO) = 0;
}

unsigned long BLOQUE_CERTPROPIO_Get_Tam (unsigned char *bloque) 
{
    return *((unsigned long *)(bloque + BYTES_CABECERA));
}


unsigned char * BLOQUE_CERTPROPIO_Get_Id (unsigned char *bloque)
{
    return bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME;

}

unsigned char * BLOQUE_CERTPROPIO_Get_Objeto(unsigned char *bloque)
{
    return (unsigned char *) bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME + BYTES_ID;
}

void BLOQUE_CERTPROPIO_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)(bloque + BYTES_CABECERA)) = tam;
}

void BLOQUE_CERTPROPIO_Set_Id(unsigned char *bloque, unsigned char id[20])
{
    memcpy(BLOQUE_CERTPROPIO_Get_Id(bloque), id, 20);
}

void BLOQUE_CERTPROPIO_Set_Objeto(unsigned char *bloque, unsigned char *cert, unsigned long tam)
{
    memcpy(BLOQUE_CERTPROPIO_Get_Objeto(bloque),cert,tam);
    BLOQUE_CERTPROPIO_Set_Tam(bloque,tam);
}


char * BLOQUE_CERTPROPIO_Get_FriendlyName (unsigned char *bloque)
{
    return (char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO);
}


void BLOQUE_CERTPROPIO_Set_FriendlyName (unsigned char *bloque, char *friendlyName)
{
    memset(bloque+BYTES_CABECERA+BYTES_TAMANYO, 0, BYTES_FRIENDLY_NAME);

    if ( friendlyName )
	strncpy((char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO), friendlyName, 30);
}


/* Utilidades para los bloques de tipo BLOQUE_CERT_RAIZ */

void BLOQUE_CERTRAIZ_Nuevo ( unsigned char *bloque )
{
    *(bloque + BYTES_TIPO) = BLOQUE_CERT_RAIZ;
}


unsigned long BLOQUE_CERTRAIZ_Get_Tam ( unsigned char *bloque )
{
    return *((unsigned long *)(bloque + BYTES_CABECERA));
}


unsigned char * BLOQUE_CERTRAIZ_Get_Objeto (unsigned char *bloque)
{
    return bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME;
}

void BLOQUE_CERTRAIZ_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)(bloque + BYTES_CABECERA)) = tam;
}


void BLOQUE_CERTRAIZ_Set_Objeto(unsigned char *bloque, unsigned char *cert, unsigned long tam)
{
    memcpy(BLOQUE_CERTRAIZ_Get_Objeto(bloque),cert,tam);
    BLOQUE_CERTRAIZ_Set_Tam(bloque,tam);
}



char * BLOQUE_CERTRAIZ_Get_FriendlyName ( unsigned char *bloque )
{
    return (char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO);
}



void BLOQUE_CERTRAIZ_Set_FriendlyName ( unsigned char *bloque, char *friendlyName )
{
    /* Si friendly name es mayor que 30 se trunca y punto
     */

    strncpy((char * )(bloque + BYTES_CABECERA + BYTES_TAMANYO), friendlyName, BYTES_FRIENDLY_NAME);
    *(bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME - 1) = 0;

}



/* Utilidades para los bloques de tipo BLOQUE_PRIVKEY_BLOB */

void BLOQUE_PRIVKEYBLOB_Nuevo(unsigned char *bloque) 
{
    *(bloque + 1) = BLOQUE_PRIVKEY_BLOB;
}

unsigned long BLOQUE_PRIVKEYBLOB_Get_Tam(unsigned char *bloque) 
{
    return *((unsigned long *)((bloque) + 8 + 1));
}

unsigned char * BLOQUE_PRIVKEYBLOB_Get_Id(unsigned char *bloque)
{
    return (bloque) + 8 + 5;
}

unsigned char * BLOQUE_PRIVKEYBLOB_Get_Objeto(unsigned char *bloque)
{
    return bloque + 8 + 25;
}

void BLOQUE_PRIVKEYBLOB_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)((bloque) + 8 + 1)) = tam;
}

void BLOQUE_PRIVKEYBLOB_Set_Id(unsigned char *bloque,unsigned char id[20])
{
    memcpy(BLOQUE_PRIVKEYBLOB_Get_Id(bloque),id,20);
}

void BLOQUE_PRIVKEYBLOB_Set_Objeto(unsigned char *bloque,unsigned char *blob,unsigned long tam)
{
    memcpy(BLOQUE_PRIVKEYBLOB_Get_Objeto(bloque),blob,tam);
    BLOQUE_PRIVKEYBLOB_Set_Tam(bloque,tam);
}



/* Certificados ajenos. BLOQUE_CERT_OTROS */

void BLOQUE_CERTOTROS_Nuevo ( unsigned char *bloque )
{
    *(bloque + BYTES_TIPO) = BLOQUE_CERT_OTROS;
    *(bloque + BYTES_CABECERA + BYTES_TAMANYO) = 0;
}


unsigned long BLOQUE_CERTOTROS_Get_Tam ( unsigned char *bloque )
{
    return *((unsigned long *)(bloque + BYTES_CABECERA));
}


unsigned char * BLOQUE_CERTOTROS_Get_Objeto (unsigned char *bloque)
{
    return bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME;
}

void BLOQUE_CERTOTROS_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)(bloque + BYTES_CABECERA)) = tam;
}


void BLOQUE_CERTOTROS_Set_Objeto(unsigned char *bloque, unsigned char *cert, unsigned long tam)
{
    memcpy(BLOQUE_CERTRAIZ_Get_Objeto(bloque),cert,tam);
    BLOQUE_CERTRAIZ_Set_Tam(bloque,tam);
}



char * BLOQUE_CERTOTROS_Get_FriendlyName ( unsigned char *bloque )
{
    return (char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO);
}



void BLOQUE_CERTOTROS_Set_FriendlyName ( unsigned char *bloque, char *friendlyName )
{
    /* Si friendly name es mayor que 30 se trunca y punto
     */

    strncpy((char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO), friendlyName, BYTES_FRIENDLY_NAME);
    *(bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME - 1) = 0;
}




/* Utilidades para los bloques de tipo BLOQUE_PUBKEY_BLOB */


void BLOQUE_PUBKEYBLOB_Nuevo(unsigned char *bloque) 
{
    *(bloque + 1) = BLOQUE_PUBKEY_BLOB;
}

unsigned long BLOQUE_PUBKEYBLOB_Get_Tam(unsigned char *bloque) 
{
    return *((unsigned long *)((bloque) + 8 + 1));
}

unsigned char * BLOQUE_PUBKEYBLOB_Get_Id(unsigned char *bloque)
{
    return (bloque) + 8 + 5;
}

unsigned char * BLOQUE_PUBKEYBLOB_Get_Objeto(unsigned char *bloque)
{
    return bloque + 8 + 25;
}

void BLOQUE_PUBKEYBLOB_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)((bloque) + 8 + 1)) = tam;
}

void BLOQUE_PUBKEYBLOB_Set_Id(unsigned char *bloque,unsigned char id[20])
{
    memcpy(BLOQUE_PRIVKEYBLOB_Get_Id(bloque),id,20);
}

void BLOQUE_PUBKEYBLOB_Set_Objeto(unsigned char *bloque,unsigned char *blob,unsigned long tam)
{
    memcpy(BLOQUE_PRIVKEYBLOB_Get_Objeto(bloque),blob,tam);
    BLOQUE_PRIVKEYBLOB_Set_Tam(bloque,tam);
}


/* Utilidades para los bloques de tipo BLOQUE_CERT_INTERMEDIO. CAs intermedias */


void BLOQUE_CERTINTERMEDIO_Nuevo ( unsigned char *bloque )
{
    *(bloque + BYTES_TIPO) = BLOQUE_CERT_INTERMEDIO;
    *(bloque + BYTES_CABECERA + BYTES_TAMANYO) = 0;
}


unsigned long BLOQUE_CERTINTERMEDIO_Get_Tam ( unsigned char *bloque )
{
    return *((unsigned long *)(bloque + BYTES_CABECERA));
}


unsigned char * BLOQUE_CERTINTERMEDIO_Get_Objeto (unsigned char *bloque)
{
    return bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME;
}

void BLOQUE_CERTINTERMEDIO_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)(bloque + BYTES_CABECERA)) = tam;
}


void BLOQUE_CERTINTERMEDIO_Set_Objeto(unsigned char *bloque, unsigned char *cert, unsigned long tam)
{
    memcpy(BLOQUE_CERTRAIZ_Get_Objeto(bloque),cert,tam);
    BLOQUE_CERTRAIZ_Set_Tam(bloque,tam);
}



char * BLOQUE_CERTINTERMEDIO_Get_FriendlyName ( unsigned char *bloque )
{
    return (char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO);
}



void BLOQUE_CERTINTERMEDIO_Set_FriendlyName ( unsigned char *bloque, char *friendlyName )
{
    /* Si friendly name es mayor que 30 se trunca y punto
     */

    strncpy((char *)(bloque + BYTES_CABECERA + BYTES_TAMANYO), friendlyName, BYTES_FRIENDLY_NAME);
    *(bloque + BYTES_CABECERA + BYTES_TAMANYO + BYTES_FRIENDLY_NAME - 1) = 0;

}








/* Utilidades para los bloques de tipo BLOQUE_CIPHER_PRIVKEY_BLOB */

void BLOQUE_CIPHPRIVKEYBLOB_Nuevo(unsigned char *bloque) 
{
    *(bloque + 1) = BLOQUE_CIPHER_PRIVKEY_BLOB;
}

unsigned long BLOQUE_CIPHPRIVKEYBLOB_Get_Tam(unsigned char *bloque) 
{
    return *((unsigned long *)((bloque) + 8 ));
}

unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Id(unsigned char *bloque)
{
    return bloque + 8 + 5;
}

unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Objeto(unsigned char *bloque)
{
    return bloque + 8 + 4 + 20 + 20 + 4 + 20 + 31;
}

unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Salt ( unsigned char *bloque )
{
	return bloque + BYTES_CABECERA + 4 + 20;
}



void BLOQUE_CIPHPRIVKEYBLOB_Set_Tam(unsigned char *bloque, unsigned long tam)
{
    *((unsigned long *)(bloque + 8)) = tam;
}

void BLOQUE_CIPHPRIVKEYBLOB_Set_Id(unsigned char *bloque,unsigned char id[20])
{
    memcpy(BLOQUE_CIPHPRIVKEYBLOB_Get_Id(bloque),id,20);
}

void BLOQUE_CIPHPRIVKEYBLOB_Set_Objeto(unsigned char *bloque,unsigned char *blob,unsigned long tam)
{
    memcpy(BLOQUE_CIPHPRIVKEYBLOB_Get_Objeto(bloque),blob,tam);
    BLOQUE_CIPHPRIVKEYBLOB_Set_Tam(bloque,tam);
}


unsigned long BLOQUE_CIPHPRIVKEYBLOB_Get_IterCount ( unsigned char *bloque )
{
	return *((unsigned long *) (bloque + BYTES_CABECERA + 4 + 20 + 20));
}

void BLOQUE_CIPHPRIVKEYBLOB_Set_IterCount ( unsigned char *bloque, unsigned long iterCount )
{
	*((unsigned long *) (bloque + BYTES_CABECERA + 4 + 20 + 20)) = iterCount;
}

void BLOQUE_CIPHPRIVKEYBLOB_Set_Salt ( unsigned char *bloque, unsigned char salt[20] )
{
	memcpy(BLOQUE_CIPHPRIVKEYBLOB_Get_Salt(bloque), salt, 20);
}


void BLOQUE_CIPHPRIVKEYBLOB_Set_Iv ( unsigned char *bloque, unsigned char iv[20] )
{
	memcpy(BLOQUE_CIPHPRIVKEYBLOB_Get_Iv(bloque), iv, 20);
}


void BLOQUE_CIPHPRIVKEYBLOB_Set_Desc( unsigned char *bloque, char ascii_desc[31] )
{
	memcpy(BLOQUE_CIPHPRIVKEYBLOB_Get_Desc(bloque), ascii_desc, 31);
}


unsigned char * BLOQUE_CIPHPRIVKEYBLOB_Get_Iv ( unsigned char *bloque )
{
	return bloque+8+4+20+20+4;
}


char * BLOQUE_CIPHPRIVKEYBLOB_Get_Desc ( unsigned char *bloque )
{
	return (char *) (bloque+8+4+20+20+4+20);
}


void BLOQUE_PUTTYKEY_Nuevo ( unsigned char *bloque )
{
	*(bloque+1) = BLOQUE_PUTTYKEY;
}

unsigned long BLOQUE_PUTTYKEY_Get_Tam(unsigned char *bloque)
{
    return *((unsigned long *)((bloque)+8));
}

unsigned char * BLOQUE_PUTTYKEY_Get_Objeto (unsigned char *bloque)
{
    return bloque+8+4;
}

void BLOQUE_PUTTYKEY_Set_Tam (unsigned char *bloque, unsigned long tam) {
    *((unsigned long *)((bloque)+8)) = tam;
}

void BLOQUE_PUTTYKEY_Set_Objeto(unsigned char *bloque, unsigned char *llave, unsigned long tam)
{
    memcpy(BLOQUE_PUTTYKEY_Get_Objeto(bloque),llave,tam);
    BLOQUE_PUTTYKEY_Set_Tam(bloque,tam);
}
