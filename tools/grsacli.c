/**
 * grsacli - RSA Cryptography Tool using GRSA
 * Gavin Cabbage - gavincabbage@gmail.com
 *
 * Compile:   $ gcc grsacli.c -o grsacli -lgmp -lgrsa
 * Usage:     $ grsacli [COMMAND] [KEYNAME] [FILENAME]
 *              COMMAND={newkey, encrypt, decrypt, sign, verify}
 * 
 * Exit codes:
 * <0> Success
 * <1> Usage error
 *
 **/



#include <grsa.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NEWKEY  "newkey"
#define ENCRYPT "encrypt"
#define DECRYPT "decrypt"
#define SIGN    "sign"
#define VERIFY  "verify"



FILE *file, *keyfile;
char *data, *keybuff;
int cmd;
grsa_key *key;

int newkey();
int encrypt();
int sign();
int verify();



int main (int argc, char *argv) /**********************************************/
{

	/* Parse command type and file names.
	 */
	if ( (argc == 3) && !strncmp(argv[1], NEWKEY) ) {
		/* Generate a new keypair. */
		/* Compute new grsa_keypair structure. */
		/* Open two keyfiles for writing. */
		/* Write public and private keys to files. */

	} else if ( (argc == 4) && !strncmp(argv[1], ENCRYPT)  {
		/* Encrypt a file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Encrypt input data with key. */
		/* Open new file and write encrypted data. */

	} else if ( (argc == 4) && !strncmp(argv[1], DECRYPT) ) {
		/* Decrypt a file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Decrypt input data with key. */
		/* Open new file and write plaintext data. */

	} else if ( (argc == 4) && !strncmp(argv[1], SIGN) ) {
		/* Sign a file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Compute signature of data with key. */
		/* Open a new file and write signature and original data. */

	} else if ( (argc == 4) && !strncmp(argv[1], VERIFY) ) {
		/* Verify a signed file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Validate signature of data with key. */
		/* Indicate success to user. */

	} else {
		fprintf(stderr, "grsacli: usage error: exit 1\n");
		exit(1);
	}

	exit(0);

} /** end main ****************************************************************/