DIR_INCLUDE = ./
DIR_SRC = ./
DIR_BIN = ./
DIR_LIB = ./

TARBALL=netjacket

AR = ar
AR_FLAGS = rs

CC = g++
CC_FLAGS = -g -O0 -Wall -I $(DIR_INCLUDE) -L $(DIR_LIB) 

PROGRAM = $(DIR_BIN)/netjacker
OBJ_PROG = Main.o
OBJ_PROG_SRC = $(DIR_SRC)/Main.cpp

MAKEFILE = Makefile
LIB_LINK = -lcrafter

$(PROGRAM):$(OBJ_PROG) $(OBJ_LIB) $(OBJ_PROTO)
	$(CC) $(CC_FLAGS) $(OBJ_PROG) $(OBJ_LIB) $(OBJ_PROTO) $(LIB_LINK) -o $(PROGRAM)

$(OBJ_PROG):$(OBJ_PROG_SRC) $(OBJ_LIB_HDR) $(MAKEFILE) 
	$(CC) -c $(OBJ_PROG_SRC) $(CC_FLAGS) 
	
$(OBJ_LIB):$(OBJ_LIB_SRC) $(OBJ_LIB_HDR) $(MAKEFILE)  
	$(CC) -c $(OBJ_LIB_SRC) $(CC_FLAGS)

clean:
	rm -rf $(OBJ_LIB) $(OBJ_PROG) $(PROGRAM) $(TARBALL).tar.gz

tarball:
	mkdir $(TARBALL)
	cp $(MAKEFILE) $(OBJ_LIB_HDR) $(OBJ_LIB_SRC) $(OBJ_PROG_SRC) $(TARBALL)/
	tar cfvz $(TARBALL).tar.gz $(TARBALL) 
	rm -rf $(TARBALL)
