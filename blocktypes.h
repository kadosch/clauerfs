
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

#ifndef __BLOCKTYPES_H__
#define __BLOCKTYPES_H__

#ifdef __cplusplus
extern "C"{
#endif

#define BLOCK_SIZE 10240


struct block_info {

    unsigned char idenString[40];
    unsigned char id[20];
    unsigned int  rzSize;           // reserved zone size
    int cb;                        // current block
    unsigned int  totalBlocks;      // total number of blocks
    unsigned int version;          // format version
    unsigned char hwId[16];
    unsigned char reserved[BLOCK_SIZE - 40 - 20 - 4 - 4 - 4 - 4 - 16]; 
};
typedef struct block_info block_info_t;


/* A block from the object zone */

struct block_object {
  /* Header */
  unsigned char mode;
  unsigned char type;
  unsigned char reservedHeader[8-2];

  /* Information */
  unsigned char info[BLOCK_SIZE - 8 - 8];

  /* padding */
  unsigned char padding[8];
};
typedef struct block_object block_object_t;


#ifdef __cplusplus
}
#endif

#endif
