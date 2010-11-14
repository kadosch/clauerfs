#define FUSE_USE_VERSION  26

#define DEVICE "/dev/sdc4"
#define MAX_DEVICE_LEN 20

#define MODO_CLARO 0xa4
#define MODO_CIFRADO 0xf9

#define BYTES_ID			20
#define BYTES_TAMANYO			4
#define BYTES_CABECERA			8
#define BYTES_FRIENDLY_NAME		31
#define BYTES_TIPO			1
   
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "blocktypes.h"
#include "UtilBloques.h"
#include "uthash.h"
#include "CRYPTOWrap.h"

struct i_clauer_handle {
  char device[MAX_DEVICE_LEN];   /* The device path (eg. "/dev/sda4") */
  int ibInit;                        /* true if the information block has been read */
  block_info_t ib;                   /* The information block of the clauer */
  int isFile;  
  int hDevice;                       /* The handle to the device */
};
typedef struct i_clauer_handle i_clauer_handle_t;

i_clauer_handle_t handle;

struct file_map{
	char file_name[35];
	int cert_block_pos;
	int key_block_pos;
	UT_hash_handle hh;
};
typedef struct file_map file_map_t;

file_map_t *fm = NULL;
char * pwd = "h0l4c4r4c0l4";

int rellenar_hash(){
	int i, j, tam;
	block_object_t data_block, data_block2, deciphered_block;
	char name[35];
	file_map_t *filemap_new;
	
	for (i=0; i < handle.ib.cb; ++i){
		if (lseek(handle.hDevice, ((i+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
			return errno;
		if (read(handle.hDevice, (void *) &data_block, BLOCK_SIZE) == -1)
			return errno;
		if (!BLOQUE_Es_Vacio((unsigned char *) &data_block) && data_block.type == BLOQUE_CERT_PROPIO){
			sprintf(name,"%s",BLOQUE_CERTPROPIO_Get_FriendlyName((unsigned char *) &data_block));
			filemap_new = (void *) malloc(sizeof(file_map_t));
			filemap_new->cert_block_pos = i;
			filemap_new->key_block_pos = -1;
			strcpy(filemap_new->file_name,name);
			for (j=0; j < handle.ib.cb; ++j){
				if (lseek(handle.hDevice, ((j+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
					return errno;
				if (read(handle.hDevice, (void *) &data_block2, BLOCK_SIZE) == -1)
					return errno;
				if (!BLOQUE_Es_Vacio((unsigned char *) &data_block2) && data_block2.type == BLOQUE_LLAVE_PRIVADA){
					CRYPTO_PBE_Descifrar(pwd, handle.ib.id, 20, 1000, 1, CRYPTO_CIPHER_DES_EDE3_CBC, data_block2.info, BLOCK_SIZE-8, deciphered_block.info, &tam);
					if (CRYPTO_X509_LLAVE(	BLOQUE_CERTPROPIO_Get_Objeto((unsigned char *) &data_block), 
											BLOQUE_CERTPROPIO_Get_Tam((unsigned char *) &data_block),
											BLOQUE_LLAVEPRIVADA_Get_Objeto((unsigned char *) &deciphered_block),
											BLOQUE_LLAVEPRIVADA_Get_Tam((unsigned char *) &deciphered_block), 
											pwd))
					{
						filemap_new->key_block_pos = j;
						break;
					}
				}
			}
			HASH_ADD_STR(fm,file_name,filemap_new);
		}
	}
	return 0;
	
}

static int clauer_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi){
	(void) offset;
	(void) fi;
	file_map_t *filemap;
	char cert[40], key[40];	
    
	if(strcmp(path, "/") != 0)
    	return -ENOENT;
  
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	
	for (filemap=fm; filemap!=NULL; filemap=filemap->hh.next){
		sprintf(cert, "%s.cert", filemap->file_name);
		filler(buf,cert,NULL,0);
		if (filemap->key_block_pos != -1){
			sprintf(key, "%s.key", filemap->file_name);
			filler(buf,key,NULL,0);
		}
	}
	 
	return 0;
}


static int clauer_getattr(const char *path, struct stat *stbuf){
	block_object_t data_block, deciphered_block;
	file_map_t *filemap;
	int res = 0, block_number, tam;
	char * name, *extension;
	
	name = strtok((char *) path+1,".");
	extension = strtok(NULL,".");

	memset(stbuf, 0, sizeof(struct stat));
	if(strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 3;
	}
	else{
 		HASH_FIND_STR(fm,name,filemap);
 		if (filemap){
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_nlink = 1;
			if (strcmp(extension,"cert")){
				block_number = filemap->cert_block_pos;
				if (lseek(handle.hDevice, ((block_number+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
					return -errno;
				if (read(handle.hDevice, &data_block, BLOCK_SIZE) == -1)
					return -errno;
				memcpy(&(stbuf->st_size), data_block.info,BYTES_TAMANYO);
			}
			else if(strcmp(extension,"key")){
				block_number = filemap->key_block_pos;
				if (block_number != -1){
					if (lseek(handle.hDevice, ((block_number+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
						return -errno;
					if (read(handle.hDevice, &data_block, BLOCK_SIZE) == -1)
						return -errno;
					CRYPTO_PBE_Descifrar( pwd, handle.ib.id, 20, 1000, 1, CRYPTO_CIPHER_DES_EDE3_CBC, data_block.info, BLOCK_SIZE-8, deciphered_block.info, &tam);
					memcpy(&(stbuf->st_size), (deciphered_block.info)+1,BYTES_TAMANYO);
				}	
			}
			else
				return -ENOENT;
		}
		else
			return -ENOENT;
	}
 
	return res;
}

static int clauer_open(const char *path, struct fuse_file_info *fi){
	file_map_t *filemap;
	char * name, *extension;
	
	name = strtok((char *) path+1,".");
	extension = strtok(NULL,".");

	//fi->direct_io = 1;
    HASH_FIND_STR(fm,name,filemap);
 	if (filemap){
		if ((fi->flags & O_ACCMODE) != O_RDONLY)
        	return -EACCES;
		return 0;
	}
	else
		return -ENOENT;
	
}

static int clauer_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	block_object_t data_block, deciphered_block;
	file_map_t *filemap;
	int block_number;
	unsigned char *obj;
	(void) fi;
	int tam;
	char * name, *extension;
	
	name = strtok((char *) path+1,".");
	extension = strtok(NULL,".");
	
	HASH_FIND_STR(fm,name,filemap);
 	if (filemap){
		if (strcmp(extension,"cert")){
			block_number = filemap->cert_block_pos;
			if (lseek(handle.hDevice, ((block_number+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
				return -errno;
			if (read(handle.hDevice, &data_block, BLOCK_SIZE) == -1)
				return -errno;
			obj = BLOQUE_CERTPROPIO_Get_Objeto((unsigned char *) &data_block);
		}
		else if (strcmp(extension,"key")){
			block_number = filemap->key_block_pos;
			if (lseek(handle.hDevice, ((block_number+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
				return -errno;
			if (read(handle.hDevice, &data_block, BLOCK_SIZE) == -1)
				return -errno;
			CRYPTO_PBE_Descifrar(pwd, handle.ib.id, 20, 1000, 1, CRYPTO_CIPHER_DES_EDE3_CBC, data_block.info, BLOCK_SIZE-8, deciphered_block.info, &tam);
			obj = BLOQUE_LLAVEPRIVADA_Get_Objeto((unsigned char *) &deciphered_block);
		}
		else
			return -ENOENT;
		memcpy(buf, obj+offset, size);
	}
	else{
		return -ENOENT;
	}
	
	return size;
}


static struct fuse_operations clauer_oper = {
    .getattr   = clauer_getattr,
    .readdir = clauer_readdir,
    .open   = clauer_open,
    .read   = clauer_read,
};

int main(int argc, char *argv[]){
	int res;
	file_map_t *current_fm;
	
	handle.hDevice = open(DEVICE,O_RDONLY);
	lseek(handle.hDevice, 0, SEEK_SET);
	strcpy(handle.device,DEVICE);
	
	if (read(handle.hDevice, (void *) &(handle.ib), BLOCK_SIZE) == -1)
		return -errno;
	handle.ibInit = 1;
	handle.isFile = 0;
	
	CRYPTO_Ini();
	if ((res = rellenar_hash()) != 0)
		return res;
    res = fuse_main(argc, argv, &clauer_oper, NULL);
    CRYPTO_Fin();
    close(handle.hDevice);
    while (fm){
		current_fm = fm;
		HASH_DEL(fm,current_fm);
		free(current_fm);
	}
    return res;
}

