[Wiki Home](https://bitbucket.org/gavincabbage/grsa/wiki/Home.md) | [Data Structures](https://bitbucket.org/gavincabbage/grsa/wiki/Data Structures.md) | [Functions](https://bitbucket.org/gavincabbage/grsa/wiki/Functions.md)

---

# grsa - RSA Cryptography Library

### Complete RSA functionality built on the GNU Multiple Precision (GMP) library.

The GRSA library is intended to provide a convenient and flexible collection of the core functions necessary to implement an
public key cryptosystem based on the RSA algorithm. Built as an abstraction on the GNU Multiple Precision (GMP) library, the
data structures and functions included are designed to easily integrate secure encryption in a variety of applications.

#### Please note that this library exists for learning purposes only and it's security is not verified!

---

### System Requirements

The GRSA library depends on the GMP library to do its number crunching. For GRSA code to compile and run, it must be properly
linked to the GMP installation on the local machine. The library has been developed and tested on 32 and 64 bit systems 
running Linux 3.5.x with Ubuntu and openSUSE distributions. 

---

### Installation

After navigating to the `grsa` directory, run `make` and `make clean` to build the library and clean up leftover object files.
Use `make test` to test the library build before running `make install` install the library in `/usr/bin`. To remove it, 
run `make uninstall` from the `grsa` directory. 

---

### Usage

To compile an executable that uses the GRSA library, use `-lgrsa -lgmp` to link the GRSA and GMP libraries in the proper
order. The source files `grsa.h` and `grsa.c` can also be compiled manually and used through a local directory include.

---

[Wiki Home](https://bitbucket.org/gavincabbage/grsa/wiki/Home.md) | [Data Structures](https://bitbucket.org/gavincabbage/grsa/wiki/Data Structures.md) | [Functions](https://bitbucket.org/gavincabbage/grsa/wiki/Functions.md)

---

Copyright (c) 2013 Gavin Cabbage. 

Please see the included MIT License for more details.
