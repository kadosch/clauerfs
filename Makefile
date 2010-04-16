clauerfs: UtilBloques.o clauerfs.c blocktypes.h uthash.h
	gcc -Wall `pkg-config fuse --cflags --libs` clauerfs.c UtilBloques.o -o clauerfs

UtilBloques.o: UtilBloques.c UtilBloques.h
	gcc -c UtilBloques.c

all: clauerfs
	
clean: 
	rm -f *.o clauerfs
	
