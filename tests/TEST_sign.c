// test file for grsa

#include <grsa.h>

int main() {

	// Plaintext.
	uchar *message = "Some text here as a sample. Not for any good purpose. Just thinking of crap to type so that I can have something to test on, ya know? Also, its messed up that Cool Breeze and Jeff don't like peaches. I mean c'mon, peaches are dank!!!";

	// Generate keypair.
	grsa_keypair *new_keypair;
	if ( grsa_generate_keypair(&new_keypair, 512, 0) != 0 ) {
		fprintf(stderr, "error generating keypair!\n");
	}

	// Compute two signatures.
	uchar *sig1 = NULL;
	uchar *sig2 = NULL;
	uint sig_len1, sig_len2;
	int ret1, ret2;
	if ( (ret1 = grsa_sign(&sig1, &sig_len1, message, strlen((char*)message), new_keypair->priv)) != 0 ) {
		fprintf(stderr, "error generating signature #1!\n");
	}
	if ( (ret2 = grsa_sign(&sig2, &sig_len2, message, strlen((char*)message), new_keypair->priv)) != 0 ) {
		fprintf(stderr, "error generating signature #2!\n");
	}
	fprintf(stderr, "ret1=%d\nret2=%d\n", ret1, ret2);

	// Corrupt 12 bytes of signature #2.
	memset(sig2+4, 0x23, 12);

	// Dump signatures.
	int i;
	fprintf(stderr, "SIGNATURE #1 DUMP:\n");
	for (i = 0; i < sig_len1; i++) {
		if ( (i % 32 == 0) && (i != 0) ) fprintf(stderr, "\n");
		fprintf(stderr, "%02x ", *(sig1+i));
	}
	fprintf(stderr, "\nSIGNATURE #2 DUMP:\n");
	for (i = 0; i < sig_len2; i++) {
		if ( (i % 32 == 0) && (i != 0) ) fprintf(stderr, "\n");
		fprintf(stderr, "%02x ", *(sig2+i));
	} fprintf(stderr, "\n");

	// Verify signatures.
	if ( (ret1 = grsa_verify(sig1, sig_len1, message, strlen((char*)message), new_keypair->pub)) > 0 ) {
		fprintf(stderr, "error verifying signature #1!\n");
	} else if (ret1 == 0) {
		fprintf(stderr, "signature #1 is valid.\n");
	} else if (ret1 == -1) {
		fprintf(stderr, "signature #1 is invalid.\n");
	}
	grsa_perror(__func__, ret1);
	if ( (ret2 = grsa_verify(sig2, sig_len2, message, strlen((char*)message), new_keypair->pub)) > 0 ) {
		fprintf(stderr, "error verifying signature #2!\n");
	} else if (ret2 == 0) {
		fprintf(stderr, "signature #2 is valid.\n");
	} else if (ret2 == -1) {
		fprintf(stderr, "signature #2 is invalid.\n");
	}
    grsa_perror(__func__, ret2);
	fprintf(stderr, "ret1=%d\nret2=%d\n", ret1, ret2);

	// Cleanup and return.
	grsa_clrkeypair(new_keypair);
	free(sig1);
	free(sig2);
	return 0;
}
