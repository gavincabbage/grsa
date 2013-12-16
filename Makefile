##
# grsa - RSA Cryptography Library (makefile)
# Gavin Cabbage - gavincabbage@gmail.com
#
##



CC=gcc
CFLAGS=-W -Wall -Wpointer-arith -O3
SOURCE=source/grsa.c
OBJECT=grsa.o
HEADER=source/grsa.h
LIBRARY=libgrsa.a
HEADER_DEST=/usr/include/grsa.h
LIBRARY_DEST=/usr/lib/libgrsa.a
TESTPATH=tests/grsa_test.c
TESTOUT=tests/test.out
TOOL=gcrypt
TOOL_SOURCE=tools/gcrypt.c
TOOL_OBJECT=gcrypt.o
TOOL_DEST=/usr/bin/gcrypt




# Build the library locally.
all: $(LIBRARY) $(TOOL)

$(LIBRARY): $(OBJECT)
	ar rcs $(LIBRARY) $(OBJECT)

$(OBJECT): $(SOURCE)
	$(CC) $(CFLAGS) -o $(OBJECT) -c $(SOURCE) -lgmp

$(TOOL): $(TOOL_SOURCE)
	$(CC) $(CFLAGS) -o $(TOOL) $(TOOL_SOURCE) -lgrsa -lgmp

clean:
	rm -f $(OBJECT)



# Install the build to /usr/bin.
install: $(HEADER_DEST) $(LIBRARY_DEST)

$(HEADER_DEST): $(HEADER)
	cp $(HEADER) $(HEADER_DEST)

$(LIBRARY_DEST): $(LIBRARY)
	cp $(LIBRARY) $(LIBRARY_DEST)

uninstall:
	rm -f $(HEADER_DEST) $(LIBRARY_DEST)



# Test library build and installation.
test: 
	$(CC) $(CFLAGS) -o $(TESTOUT) $(TESTPATH) -lgrsa -lgmp
	./$(TESTOUT)
	rm -f $(TESTOUT)

