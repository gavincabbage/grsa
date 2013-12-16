/**
 * grsacli - RSA Cryptography Tool using GRSA
 * Gavin Cabbage - gavincabbage@gmail.com
 *
 * Compile:   $ gcc grsacli.c -o grsacli -lgmp -lgrsa
 * Usage:     $ grsacli [COMMAND] [ARGS...]
 *              COMMAND={newkey, keyinfo, encrypt, decrypt, sign, verify}
 * 
 * Exit codes:
 * <0> Success
 * <1> Usage error
 * <2> Memory allocation error.
 * <3> Error exporting key.
 * <4> Error opening file.
 * <5> Error writing key data to file.
 *
 * New keys are written to .gkey files.
 * <4 bytes> Magic number 1.
 * <4 bytes> Magic number 2.
 * <4 bytes> Public/private flag, 1 or 2 respectively.
 * <4 bytes> Key size, in bits.
 * <4 bytes> Key data size, n.
 * <n bytes> Key data.
 *
 * Future plans:
 * <> First of all, finish the thing in its basic form.
 * <> Add user and date information to keyfile format.
 * <> Improve file read/write and header design.
 *
 **/



#include <grsa.h> /* typedefs uint and uchar */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>



int magic1 = 0x42424242;
int magic2 = 0xcabba6e5;
int headsize = 20; /* 5 integers at 4 bytes each */
int pubflag = 1;
int priflag = 2;

void error(int code, char *info);



int main (int argc, char *argv[]) /**********************************************/
{

	/* Parse command (argv[1]) and validate arguments.
	 */
	if ( (argc == 2) && !strncmp(argv[1], "help", strlen("help")) ) {
		/* Print help message. */

	} else if ( (argc == 4) && !strncmp(argv[1], "newkey", strlen("newkey")) ) {

		/* Generate a new keypair: $ grsacli newkey [KEYNAME] [BITS] */
		grsa_keypair *keypair;
		uchar *publicbuffer, *privatebuffer;
		int publicfile, privatefile, bits, filename_length, filesize, written;
		uint pubsize, prisize;

		/* Compute new grsa_keypair structure. */
		bits = strtol(argv[3], NULL, 10);
		grsa_generate_keypair(&keypair, bits, 0);

		/* Export keys. */
		if ( grsa_export(&publicbuffer, &pubsize, keypair->pub) != 0 ) {
			error(3, "public");
		}
		if ( grsa_export(&privatebuffer, &prisize, keypair->priv) != 0 ) {
			error(3, "private");
		}

		/* Open two files for writing: KEYNAME.pub.gkey and KEYNAME.pri.gkey,
		 * to hold the public and private keys, respectively. */
		filename_length = strlen(argv[2])+strlen(".xxx.gkey")+1;
		char publicname[filename_length], privatename[filename_length];
		snprintf(publicname, filename_length, "%s.pub.gkey", argv[2]);
		snprintf(privatename, filename_length, "%s.pri.gkey", argv[2]);
		fprintf(stderr, "[DEBUG] pub: %s, pri: %s\n", publicname, privatename);
		if ( (publicfile = open(publicname, O_CREAT|O_WRONLY, 0700)) < 0 ) {
			error(4, publicname);
		}
		if ( (privatefile = open(privatename, O_CREAT|O_WRONLY, 0700)) < 0 ) {
			error(4, privatename);
		}
		fprintf(stderr, "[DEBUG] got files open, pub: %d, pri: %d\n", publicfile, privatefile);

		/* Write public key header and data to file. */
		filesize = headsize + pubsize;
		written = write(publicfile, (char*)&magic1, sizeof(magic1));
		written += write(publicfile, (char*)&magic2, sizeof(magic2));
		written += write(publicfile, (char*)&pubflag, sizeof(int));
		written += write(publicfile, (char*)&bits, sizeof(bits));
		written += write(publicfile, (char*)&pubsize, sizeof(pubsize));
		written += write(publicfile, publicbuffer, pubsize);
		if ( written != filesize ) {
			fprintf (stderr, "[DEBUG] written: %d, filesize: %d\n", written, filesize);
			error(5, "public");
		}
		close(publicfile);

		/* Write private key header and data to file. */
		filesize = headsize + prisize;
		written = write(privatefile, (char*)&magic1, sizeof(magic1));
		written += write(privatefile, (char*)&magic2, sizeof(magic2));
		written += write(privatefile, (char*)&priflag, sizeof(int));
		written += write(privatefile, (char*)&bits, sizeof(bits));
		written += write(privatefile, (char*)&prisize, sizeof(prisize));
		written += write(privatefile, privatebuffer, prisize);
		if ( written != filesize ) {
			fprintf (stderr, "[DEBUG] written: %d, filesize: %d\n", written, filesize);
			error(5, "private");
		}
		close(privatefile);


	} else if ( (argc == 3) && !strncmp(argv[1], "keyinfo", strlen("keyinfo")) ) {

		/* Display a keyfile's information to the terminal. */
		int keyfile, got_magic1, got_magic2, got_flag, got_bits, got_size, rd;

		/* Open the keyfile and read header information. */
		if ( (keyfile = open(argv[2], O_RDONLY)) < 0 ) {
			error(4, argv[2]);
		}
		rd = read(keyfile, (char*)&got_magic1, sizeof(got_magic1));
		rd += read(keyfile, (char*)&got_magic2, sizeof(got_magic2));
		rd += read(keyfile, (char*)&got_flag, sizeof(got_magic1));
		rd += read(keyfile, (char*)&got_bits, sizeof(got_magic1));
		rd += read(keyfile, (char*)&got_size, sizeof(got_magic1));
		close(keyfile);

		/* Report key information to stdout. */
		fprintf(stdout, "gcrypt: report on file <%s>\n", argv[2]);
		if ( (got_magic1 != magic1) || 
			 (got_magic2 != magic2) || 
			 (rd != headsize )       )
		{
			fprintf(stdout, "> the file does not contain a grsa key\n");
		} else {
			if (got_flag == pubflag) {
				fprintf(stdout, "> file contains a grsa public key\n");
			} else if (got_flag == priflag) {
				fprintf(stdout, "> file contains a grsa private key\n");
			} else {
				fprintf(stdout, "> file contains a grsa key of unspecified type\n");
			}
			fprintf(stdout, "> the key is %d bits\n", got_bits);
			fprintf(stdout, "> the key data is %d bytes long\n", got_size);
		}
		fprintf(stdout, "gcrypt: end report: exit 0\n");


	} else if ( (argc == 4) && !strncmp(argv[1], "encrypt", strlen("encrypt")) ) {
		/* Encrypt a file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Encrypt input data with key. */
		/* Open new file and write encrypted data. */


	} else if ( (argc == 4) && !strncmp(argv[1], "decrypt", strlen("decrypt")) ) {
		/* Decrypt a file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Decrypt input data with key. */
		/* Open new file and write plaintext data. */


	} else if ( (argc == 4) && !strncmp(argv[1], "sign", strlen("sign")) ) {
		/* Sign a file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Compute signature of data with key. */
		/* Open a new file and write signature and original data. */


	} else if ( (argc == 4) && !strncmp(argv[1], "verify", strlen("verify")) ) {
		/* Verify a signed file. */
		/* Open and read in files. */
		/* Initialize grsa_key structure from keyfile data. */
		/* Validate signature of data with key. */
		/* Indicate success to user. */


	} else {
		error(1, argv[1]);
	}


	exit(0);

} /** end main ****************************************************************/


/* Print the appropriate error message and exit. */
void error(int code, char *info) {
	fprintf(stderr, "gcrypt: ");
	switch(code) {
	case 1:
		fprintf(stderr, "usage error, command <%s>: exit 1\n", info);
		exit(1); break;
	case 2:
		fprintf(stderr, "memory allocation error: exit 2\n");
		exit(2); break;
	case 3:
		fprintf(stderr, "error exporting %s key: exit 4\n", info);
		exit(3); break;
	case 4:
		fprintf(stderr, "error opening file <%s>: exit 3\n", info);
		exit(4); break;
	case 5:
		fprintf(stderr, "error writing %s key data to file: exit 5\n", info);
		exit(5); break;
	default:
		fprintf(stderr, "undefined exit code: exit %d", code);
		exit(code); break;
	}
}