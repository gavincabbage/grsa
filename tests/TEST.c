// test file for grsa

#include <grsa.h>

int main() {

	// Generate keypair.
	grsa_keypair *new_keypair;
	int retval;
	if ( (retval = grsa_generate_keypair(&new_keypair, 32, 0)) != 0 ) {
		grsa_perror("grsa_generate_keypair", retval);
	}


	gmp_printf("\nPUB MODULUS: 0x%Zx\n", new_keypair->pub->modulus);
	gmp_printf("PUB EXPONENT: 0x%Zx\n", new_keypair->pub->exponent);
	gmp_printf("PUB BYTES: %d\n", new_keypair->pub->bytes);
	gmp_printf("PRIV MODULUS: 0x%Zx\n", new_keypair->priv->modulus);
	gmp_printf("PRIV EXPONENT: 0x%Zx\n", new_keypair->priv->exponent);
	gmp_printf("PRIV BYTES: %d\n", new_keypair->priv->bytes);


	// Export keypair.
	uchar *pub_buf;
	uchar *priv_buf;
	uint pub_len, priv_len;
	//grsa_key *pub, priv;
	//pub = malloc(sizeof(grsa_key));
	//priv = malloc(sizeof(grsa_key));
	//*pub = new_keypair->pub;
	//*priv = new_keypair->priv;
	grsa_export(&pub_buf, &pub_len, new_keypair->pub);
	grsa_export(&priv_buf, &priv_len, new_keypair->priv);

	// Print data buffer.
    fprintf(stderr, "\n---------\n");
	uint i;
	for (i = 0; i < pub_len; i++) {
		fprintf(stderr, "%02x ", (int)*(pub_buf+i));
		if ((i+1) % 16 == 0) fprintf(stderr, "\n");
	} fprintf(stderr, "\n");
	fprintf(stderr, "\n---------\n");
	for (i = 0; i < pub_len; i++) {
		fprintf(stderr, "%02x ", (int)*(priv_buf+i));
		if ((i+1) % 16 == 0) fprintf(stderr, "\n");
	} fprintf(stderr, "\n");
	fprintf(stderr, "\n---------\n");



	// Import keypair.
	grsa_keypair *imported_keypair;
	imported_keypair = malloc(sizeof(grsa_keypair));
	grsa_import(&imported_keypair->pub, pub_buf, pub_len);
	grsa_import(&imported_keypair->priv, priv_buf, priv_len);

	// Verify keypair.
	retval = grsa_verify_keypair(imported_keypair);
    grsa_perror("grsa_verify_keypair", retval);


	gmp_printf("\nPUB MODULUS: 0x%Zx\n", imported_keypair->pub->modulus);
	gmp_printf("PUB EXPONENT: 0x%Zx\n", imported_keypair->pub->exponent);
	gmp_printf("PUB BYTES: %d\n", imported_keypair->pub->bytes);
	gmp_printf("PRIV MODULUS: 0x%Zx\n", imported_keypair->priv->modulus);
	gmp_printf("PRIV EXPONENT: 0x%Zx\n", imported_keypair->priv->exponent);
	gmp_printf("PRIV BYTES: %d\n", imported_keypair->priv->bytes);


	free(pub_buf);
	free(priv_buf);
	grsa_clrkeypair(new_keypair);
	grsa_clrkeypair(imported_keypair);

	return 0;
}
