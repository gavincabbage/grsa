 ##############################################################################
 #                                                                            #
 #               grsa - RSA Cryptography Library (makefile)                   #
 #               Gavin Cabbage - gavincabbage@gmail.com                       #
 #                                                                            #
 ##############################################################################



CC=gcc
CFLAGS=-W -Wall -Wpointer-arith -O3 -lgmp

SOURCE=grsa.c
HEADER=grsa.h
OBJECT=grsa.o
LIBRARY=libgrsa.a
TESTPATH=tests/grsa_test.c
TESTOUT=tests/test.out
HEADER_DEST=/usr/include/grsa.h
LIBRARY_DEST=/usr/lib/libgrsa.a



# Build the library locally.
all: $(LIBRARY)

$(LIBRARY): $(OBJECT)
	ar rcs $(LIBRARY) $(OBJECT)

$(OBJECT): $(SOURCE)
	$(CC) -o $(OBJECT) -c $(SOURCE)

clean:
	rm -f $(OBJECT)



# Install the build to /usr/bin
install: $(HEADER_DEST) $(LIBRARY_DEST)

$(HEADER_DEST): $(HEADER)
	cp $(HEADER) $(HEADER_DEST)

$(LIBRARY_DEST): $(LIBRARY)
	cp $(LIBRARY) $(LIBRARY_DEST)

uninstall:
	rm -f $(HEADER_DEST) $(LIBRARY_DEST)



# Test library build and installation.
test: 
	gcc -o $(TESTOUT) $(TESTPATH) -lgrsa -lgmp
	./$(TESTOUT)
	rm -f $(TESTOUT)
