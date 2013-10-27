/**
 * GRSA Test #1 - Key generation, key import and export
 **/



#include "../grsa.h"



int test_num = 0;
void _msg(char *msg) fprintf(stderr, "test %d: %s", ++test_num, msg);
void _result(int retval, int expval) {
  if (retval == expval) fprintf(stderr, "success.\n");
  else {
    fprintf(stderr, "fail!\n\texpected %d, got %d\n\tperror: ");
    perror(" - ", retval);
  }
}
  


int main() 
{

  int retval, expval;
  grsa_keypair *dummy, *kp32, *kp512, *kp1024, *kp2048, *kp4096, *kp8192;


  /* Key generation, import and export. 
   */

  _msg("invalid keysize..."); expval = ARG_ERR;
  retval = grsa_generate_keypair()
  _result(retval, expval);







	grsa_keypair *kpfail, *kp32, *kp512, *kp1024, *kp2048, *kp4096, *kp8192;
    if ( grsa_generate_keypair(&kpfail, 8, 0) == 0 ) {

    }








	grsa_keypair *new_keypair;
	if ( grsa_generate_keypair(&new_keypair, 2048, 0) != 0 ) {
		fprintf(stderr, "error generating keypair: exit 1\n");
		exit(1);
	}

	gmp_printf("PUB MODULUS: 0x%Zx\n", new_keypair->pub->modulus);
	gmp_printf("PUB EXPONENT: 0x%Zx\n", new_keypair->pub->exponent);
	gmp_printf("PUB BYTES: %d\n", new_keypair->pub->bytes);
	gmp_printf("PRIV MODULUS: 0x%Zx\n", new_keypair->priv->modulus);
	gmp_printf("PRIV EXPONENT: 0x%Zx\n", new_keypair->priv->exponent);
	gmp_printf("PRIV BYTES: %d\n", new_keypair->priv->bytes);
	
	int result = grsa_verify_keypair(new_keypair);
	gmp_printf("Verified? %d\n", result);

	grsa_clrkeypair(new_keypair);


	return result;
}
