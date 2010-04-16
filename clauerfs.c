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
	int file_block_pos;
	UT_hash_handle hh;
};
typedef struct file_map file_map_t;

file_map_t *fm = NULL;

int rellenar_hash(){
	int i;
	block_object_t data_block;
	char name[35], friendly[15];
	file_map_t *filemap, *filemap_new;
	
	for (i=0; i < handle.ib.cb; ++i){
		if (lseek(handle.hDevice, ((i+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
			return errno;
		if (read(handle.hDevice, (void *) &data_block, BLOCK_SIZE) == -1)
			return errno;
		if (data_block.mode == MODO_CLARO && data_block.type != BLOQUE_KEY_CONTAINERS){
			switch (data_block.type){
				case BLOQUE_CERT_PROPIO:
					sprintf(friendly,"%s",BLOQUE_CERTPROPIO_Get_FriendlyName((unsigned char *) &data_block));
					break;
				case BLOQUE_CERT_RAIZ:
					sprintf(friendly,"%s",BLOQUE_CERTRAIZ_Get_FriendlyName((unsigned char *) &data_block));
					break;
				case BLOQUE_CERT_INTERMEDIO:
					sprintf(friendly,"%s", BLOQUE_CERTINTERMEDIO_Get_FriendlyName((unsigned char *) &data_block));
					break;
				case BLOQUE_CERT_OTROS:
					sprintf(friendly,"%s", BLOQUE_CERTOTROS_Get_FriendlyName((unsigned char *) &data_block));
					break;
				default:
					sprintf(friendly,"%s","");
			}
			if (strlen(friendly)>0)
				sprintf(name,"%s_%s",BLOQUE_Tipo_Str((unsigned char *) &data_block),friendly);
			else
				sprintf(name,"%s",BLOQUE_Tipo_Str((unsigned char *) &data_block));
			
			HASH_FIND_STR(fm, name, filemap);
			if (filemap){
				sprintf(name,"%s_%s",name,"OTRO");
			}
			filemap_new = (void *) malloc(sizeof(file_map_t));
			filemap_new->file_block_pos = i;
			strcpy(filemap_new->file_name,name);
			HASH_ADD_STR(fm,file_name,filemap_new);
		}
	}
	return 0;
	
}

static int clauer_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi){
	(void) offset;
	(void) fi;
	file_map_t *filemap;
    
	if(strcmp(path, "/") != 0)
    	return -ENOENT;
  
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	
	for (filemap=fm; filemap!=NULL; filemap=filemap->hh.next){
		filler(buf,filemap->file_name,NULL,0);
	}
	 
	return 0;
}


static int clauer_getattr(const char *path, struct stat *stbuf){
	block_object_t data_block;
	file_map_t *filemap;
	int res = 0, block_number;
	
	memset(stbuf, 0, sizeof(struct stat));
	if(strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 3;
	}
	else{
 		HASH_FIND_STR(fm,path+1,filemap);
 		if (filemap){
			block_number = filemap->file_block_pos;
			if (lseek(handle.hDevice, ((block_number+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
				return -errno;
			if (read(handle.hDevice, &data_block, BLOCK_SIZE) == -1)
				return -errno;
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_nlink = 1;
			switch (data_block.type){
				case BLOQUE_LLAVE_PRIVADA:
					//stbuf->st_size = BLOQUE_LLAVEPRIVADA_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), (data_block.info)+1,BYTES_TAMANYO);
					break;
				case BLOQUE_CERT_PROPIO:
					//stbuf->st_size = BLOQUE_CERTPROPIO_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), data_block.info,BYTES_TAMANYO);
					break;
				case BLOQUE_CERT_RAIZ:
					//stbuf->st_size = BLOQUE_CERTRAIZ_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), data_block.info,BYTES_TAMANYO);
					break;
				case BLOQUE_PRIVKEY_BLOB:
					//stbuf->st_size = BLOQUE_PRIVKEYBLOB_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), (data_block.info)+1,BYTES_TAMANYO);
					break;
				case BLOQUE_PUBKEY_BLOB:
					//stbuf->st_size = BLOQUE_PUBKEYBLOB_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), (data_block.info)+1,BYTES_TAMANYO);
					break;
				case BLOQUE_CERT_INTERMEDIO:
					//stbuf->st_size = BLOQUE_CERTINTERMEDIO_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), data_block.info,BYTES_TAMANYO);
					break;
				case BLOQUE_CERT_OTROS:
					//stbuf->st_size = BLOQUE_CERTOTROS_Get_Tam(data_block);
					memcpy(&(stbuf->st_size), data_block.info,BYTES_TAMANYO);
					break;
				case BLOQUE_CRYPTO_WALLET:
					stbuf->st_size = BLOCK_SIZE-16;
					break;
				default:
					stbuf->st_size = 0;
					break;
			}			
		}
		else
			return -ENOENT;
	}
 
	return res;
}

static int clauer_open(const char *path, struct fuse_file_info *fi){
	file_map_t *filemap;

	//fi->direct_io = 1;
    HASH_FIND_STR(fm,path+1,filemap);
 	if (filemap){
		if ((fi->flags & O_ACCMODE) != O_RDONLY)
        	return -EACCES;
		return 0;
	}
	else
		return -ENOENT;
	
}

static int clauer_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi){
	block_object_t data_block;
	file_map_t *filemap;
	int block_number;
	unsigned char *obj;
	(void) fi;
	
	HASH_FIND_STR(fm,path+1,filemap);
 	if (filemap){
		block_number = filemap->file_block_pos;
		if (lseek(handle.hDevice, ((block_number+1)*BLOCK_SIZE)+(handle.ib.rzSize*BLOCK_SIZE), SEEK_SET) == -1)
			return -errno;
		if (read(handle.hDevice, &data_block, BLOCK_SIZE) == -1)
			return -errno;
	
		switch (data_block.type){
			case BLOQUE_LLAVE_PRIVADA:
				obj = BLOQUE_LLAVEPRIVADA_Get_Objeto((unsigned char *) &data_block);
				break;
			case BLOQUE_CERT_PROPIO:
				obj = BLOQUE_CERTPROPIO_Get_Objeto((unsigned char *) &data_block);
				break;
			case BLOQUE_CERT_RAIZ:
				obj = BLOQUE_CERTRAIZ_Get_Objeto((unsigned char *) &data_block);
				break;
			case BLOQUE_PRIVKEY_BLOB:
				obj = BLOQUE_PRIVKEYBLOB_Get_Objeto((unsigned char *) &data_block);
				break;
			case BLOQUE_PUBKEY_BLOB:
				obj = BLOQUE_PUBKEYBLOB_Get_Objeto((unsigned char *) &data_block);
				break;
			case BLOQUE_CERT_INTERMEDIO:
				obj = BLOQUE_CERTINTERMEDIO_Get_Objeto((unsigned char *) &data_block);
				break;
			case BLOQUE_CERT_OTROS:
				obj = BLOQUE_CERTOTROS_Get_Objeto((unsigned char *) &data_block);
				break;
			default:
				return -ENOENT;
	
		}
		memcpy(buf, obj+offset, size);
		//strncpy((char *) buf, (char *) (obj+offset), size);
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
	
	if ((res = rellenar_hash()) != 0)
		return res;
    res = fuse_main(argc, argv, &clauer_oper, NULL);
    close(handle.hDevice);
    while (fm){
		current_fm = fm;
		HASH_DEL(fm,current_fm);
		free(current_fm);
	}
    return res;
}

