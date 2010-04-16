
/*

                        LICENCIA

1. Este programa puede ser ejecutado sin ninguna restricci�n
   por parte del usuario final del mismo.

2. La  Universitat Jaume I autoriza la copia y  distribuci�n
   del programa con cualquier fin y por cualquier medio  con
   la  �nica limitaci�n de que, de forma  apropiada, se haga
   constar  en  cada  una  de las copias la  autor�a de esta  
   Universidad  y  una reproducci�n  exacta de las presentes 
   condiciones   y   de   la   declaraci�n  de  exenci�n  de 
   responsabilidad.

3. La  Universitat  Jaume  I autoriza  la  modificaci�n  del
   software  y  su  redistribuci�n  siempre que en el cambio
   del  c�digo  conste la autor�a de la Universidad respecto  
   al  software  original  y  la  url de descarga del c�digo
   fuente  original. Adem�s, su denominaci�n no debe inducir 
   a  error  o  confusi�n con el original. Cualquier persona
   o  entidad  que  modifique  y  redistribuya  el  software 
   modificado deber�  informar de tal circunstancia mediante
   el  env�o  de  un  mensaje  de  correo  electr�nico  a la 
   direcci�n  clauer@uji.es  y  remitir una copia del c�digo 
   fuente modificado.

4. El  c�digo  fuente  de todos los programas amparados bajo 
   esta licencia  est�  disponible para su descarga gratuita
   desde la p�gina web http//:clauer.uji.es.

5. El hecho en s� del uso, copia o distribuci�n del presente 
   programa implica la aceptaci�n de estas condiciones.

6. La  copia y distribuci�n del programa supone la extensi�n 
   de las presentes condiciones al destinatario.
   El  distribuidor no puede imponer condiciones adicionales
   que limiten las aqu� establecidas.

       DECLARACI�N DE EXENCI�N DE RESPONSABILIDAD

Este  programa  se  distribuye  gratuitamente. La Universitat 
Jaume  I  no  ofrece  ning�n  tipo de garant�a sobre el mismo
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
