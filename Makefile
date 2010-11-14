clauerfs: UtilBloques.o CRYPTOWrap.o clauerfs.c blocktypes.h uthash.h 
	gcc  -Wall `pkg-config fuse --cflags --libs` `pkg-config openssl --cflags --libs` clauerfs.c UtilBloques.o  CRYPTOWrap.o -o clauerfs -g3

UtilBloques.o: UtilBloques.c UtilBloques.h
	gcc -c UtilBloques.c -g3
	
CRYPTOWrap.o: CRYPTOWrap.c CRYPTOWrap.h
	gcc -I. -I. -O4 -DLINUX -DIAx86_64 -I/include -L/usr/lib64 -I/usr/include/openssl -O2 -c CRYPTOWrap.c -o CRYPTOWrap.o -g3

all: clauerfs
	
clean: 
	rm -f *.o clauerfs
	
