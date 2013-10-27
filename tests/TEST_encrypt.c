// encrypt/decrypt testing for grsa

#include <grsa.h>
  
int main() {

	int printw = 32;

	grsa_keypair *new_keypair;
	if ( grsa_generate_keypair(&new_keypair, 1024, 0) != 0 ) {
		fprintf(stderr, "error generating keypair: exit 1\n");
		exit(1);
	}

	unsigned char *message = "Water, water, everywhere, and not a drop to drink. I really like this single line, but have never read the whole poem. I really should!";
	unsigned char *ciphertext = NULL;

	fprintf(stderr, "MESSAGE: %s\nMESSAGE DUMP >> >> >>\n", message);
	uint i;
	for (i = 0; i < strlen((char*)message); i++) {
		if ( (i % printw == 0) && (i != 0) ) fprintf(stderr, "\n");
		fprintf(stderr, "%02x", *(message+i));
	} fprintf(stderr, "\n<< << << END MESSAGE DUMP");

	// encrypt message
	uint clen;
	int retval = grsa_encrypt(&ciphertext, &clen, message, strlen((char*)message), new_keypair->pub, ENCODE_RANDOM, 32);
	fprintf(stderr, "CIPHERTEXT: %s\n", ciphertext);
	fprintf(stderr, "retval=%d\n", retval);


	fprintf(stderr, "CIPHERTEXT DUMP >> >> >>\n");
	for (i = 0; i < clen; i++) {
		if ( (i % printw == 0) && (i != 0) ) fprintf(stderr, "\n");
		fprintf(stderr, "%02x", *(ciphertext+i));
	} fprintf(stderr, "\n<< << << END CIPHERTEXT DUMP");


	uchar *plaintext = NULL;
	uint plen;
	retval = grsa_decrypt(&plaintext, &plen, ciphertext, clen, new_keypair->priv, ENCODE_RANDOM, 32);
	fprintf(stderr, "DECRYPT DUMP >> >> >>\n");
	for (i = 0; i < plen; i++) {
		if ( (i % printw == 0) && (i != 0) ) fprintf(stderr, "\n");
		fprintf(stderr, "%02x", *(plaintext+i));
	} fprintf(stderr, "\n<< << << END DECRYPT DUMP");

	fprintf(stderr, "\nretval=%d\n", retval);

	free(ciphertext);

	//fprintf(stderr, "%c%c%c", *(ciphertext), *(ciphertext+1), *(ciphertext+2));
	//int i; 
	//for (i = 0; i < strlen(message); i++) {
	//	fprintf(stderr, "%c", *(ciphertext+i));
	//}

	//char *decrypted = NULL;
	// decrypt message
	//grsa_decrypt(decrypted, ciphertext, strlen(ciphertext), new_keypair->priv, ENCODE_RANDOM, 1);
	//fprintf(stderr, "DECRYPTED: %s\n", decrypted);

	free(plaintext);
	grsa_clrkeypair(new_keypair);
	exit(0);
}

