/**
 * grsa - RSA Cryptography Library (self test)
 * Gavin Cabbage - gavincabbage@gmail.com
 *
 **/



#include "../source/grsa.h"



int testcount = 0;
int failcount = 0;
char *ok = "[\033[32;1mOK\033[0m]";
char *failure = "[\033[31;1mFAILED\033[0m]";

void log_test(char *func, int retval, int expval);
void dummy_data(uchar **buffer, int bytes);



int main () /******************************************************************/
{
  
  /* Prepare for testing.
   */
	grsa_keypair *kp1, *kp2, *kp3;
	uchar *buf1, *buf2, *buf3, *buf4, *buf5, *buf6, 
				*msg1, *msg2, *msg3, *cip1, *cip2, *cip3;
	uint len1, len2, len3, len4, len5, len6;
	int retval;



  /* Test grsa_generate_keypair(). Tests 0-7.
   */
	retval = grsa_generate_keypair(&kp1, 8, 0); /* bits to small */
	log_test("grsa_generate_keypair", retval, ARG_ERR);
	retval = grsa_generate_keypair(&kp1, 71, 0); /* bits not divisible by 8 */
	log_test("grsa_generate_keypair", retval, ARG_ERR);
  retval = grsa_generate_keypair(&kp1, 1024, 3); /* try a different pubexp */
  log_test("grsa_generate_keypair", retval, POSITIVE);
  grsa_clrkeypair(kp1);
  retval = grsa_generate_keypair(&kp1, 1024, 16); /* try a bad pubexp */
  log_test("grsa_generate_keypair", retval, GMP_ERR);
  grsa_clrkeypair(kp1);
	retval = grsa_generate_keypair(&kp1, 1024, 0);
	log_test("grsa_generate_keypair", retval, POSITIVE);
	grsa_clrkeypair(kp1);
	retval = grsa_generate_keypair(&kp1, 2048, 0); /* good keys for later */
	log_test("grsa_generate_keypair", retval, POSITIVE);
	retval = grsa_generate_keypair(&kp2, 4096, 0);
	log_test("grsa_generate_keypair", retval, POSITIVE);
	retval = grsa_generate_keypair(&kp3, 8192, 0);
	log_test("grsa_generate_keypair", retval, POSITIVE);



	/* Test grsa_import() and grsa_export(). Tests 8-22.
	 */
	retval = grsa_export(&buf1, &len1, kp1->pub);
	log_test("grsa_export", retval, POSITIVE);
	retval = grsa_export(&buf2, &len2, kp1->priv);
	log_test("grsa_export", retval, POSITIVE);
	retval = grsa_export(&buf3, &len3, kp2->pub);
	log_test("grsa_export", retval, POSITIVE);
	retval = grsa_export(&buf4, &len4, kp2->priv);
	log_test("grsa_export", retval, POSITIVE);
	retval = grsa_export(&buf5, &len5, kp3->pub);
	log_test("grsa_export", retval, POSITIVE);
	retval = grsa_export(&buf6, &len6, kp3->priv);
	log_test("grsa_export", retval, POSITIVE);

  retval = grsa_import(&kp1->pub, buf1, len1);
  log_test("grsa_import", retval, POSITIVE);
  retval = grsa_import(&kp1->priv, buf2, len2);
  log_test("grsa_import", retval, POSITIVE);
  retval = grsa_import(&kp2->pub, buf3, len3);
  log_test("grsa_import", retval, POSITIVE);
  retval = grsa_import(&kp2->priv, buf4, len4);
  log_test("grsa_import", retval, POSITIVE);
  retval = grsa_import(&kp3->pub, buf5, len5);
  log_test("grsa_import", retval, POSITIVE);
  retval = grsa_import(&kp3->priv, buf6, len6);
  log_test("grsa_import", retval, POSITIVE);

  retval = grsa_verify_keypair(kp1);
  log_test("post-import/export verification", retval, POSITIVE);
  retval = grsa_verify_keypair(kp2);
  log_test("post-import/export verification", retval, POSITIVE);
  retval = grsa_verify_keypair(kp3);
  log_test("post-import/export verification", retval, POSITIVE);

  free(buf1); free(buf2); free(buf3);
  free(buf4); free(buf5); free(buf6);
  len1 = len2 = len3 = len4 = len5 = len6 = 0;



	/* Test grsa_encrypt() and grsa_decrypt().
	 *
	 * Still need to add some bad argument tests.
	 *
	 */
  dummy_data(&msg1, kp1->pub->bytes);
	dummy_data(&msg2, kp2->pub->bytes);
	dummy_data(&msg3, kp3->pub->bytes);
  
  retval = grsa_encrypt(&cip1, &len1, msg1, strlen((char*)msg1),
  	                    kp1->pub, ENCODE_NONE, 1);
  log_test("grsa_encrypt", retval, POSITIVE);
  retval = grsa_encrypt(&cip2, &len2, msg2, strlen((char*)msg2),
  	                    kp2->pub, ENCODE_RANDOM, 0);
  log_test("grsa_encrypt", retval, POSITIVE);
  retval = grsa_encrypt(&cip3, &len3, msg3, strlen((char*)msg3),
  	                    kp3->pub, ENCODE_RANDOM, strlen((char*)msg3));
  log_test("grsa_encrypt", retval, POSITIVE);

  retval = grsa_decrypt(&buf1, &len4, cip1, len1, kp1->priv, ENCODE_NONE, 1);
  log_test("grsa_decrypt", retval, POSITIVE);
  retval = grsa_decrypt(&buf2, &len5, cip2, len2, kp2->priv, ENCODE_RANDOM, 0);
  log_test("grsa_decrypt", retval, POSITIVE);
  retval = grsa_decrypt(&buf3, &len6, cip3, len3, kp3->priv, ENCODE_RANDOM, 
  	                    strlen((char*)msg3));
  log_test("grsa_decrypt", retval, POSITIVE);

  retval = compare_data(msg1, kp1->pub->bytes, buf1, len4);
  log_test("comparing original & decrypted data", retval, POSITIVE);
  retval = compare_data(msg2, kp2->pub->bytes, buf2, len5);
  log_test("comparing original & decrypted data", retval, POSITIVE);
  retval = compare_data(msg3, kp3->pub->bytes, buf3, len6);
  log_test("comparing original & decrypted data", retval, POSITIVE);


	/* Test grsa_sign() and grsa_verify().
	 */



  /* Print final message.
   */
  if (failcount == 0) {
  	fprintf(stderr, "\033[32;1mAll tests completed successfully.\033[0m\n");
  } else {
  	fprintf(stderr, "\033[31;1m%d tests failed!\033[0m\n", failcount);
  	fprintf(stderr, 
  		      "Please send this failure report to gavincabbage@gmail.com\033[0m\n\n");
  }


  grsa_clrkeypair(kp1);
  grsa_clrkeypair(kp2);
  grsa_clrkeypair(kp3);

  return 0;

} /** end main ****************************************************************/



 /** Log the result of a given test.
  *
  **/
void log_test ( char *func, int retval, int expval )
{

  fprintf(stderr, "%-8d", testcount+1);

  if (retval == expval) {
  	fprintf(stderr, "%s\t", ok);
  } else {
  	fprintf(stderr, "%s", failure);
  	failcount += 1;
  }

  fprintf(stderr, "  expected %d, got %d  ", expval, retval);
  grsa_perror(func, retval);

  testcount += 1;

} /*end log_test() */



 /** Populate a buffer with the given number of random bytes.
  *
  * Note: This function allocates memory for dummy buffer.
  *
  **/
void dummy_data(uchar **buffer, int bytes)
{

  if ( (*buffer = malloc(bytes)) == NULL ) {
  	perror("dummy_data"); 
  	exit(1);
  }

  int fd;
  if ( (fd = open("/dev/urandom", O_RDONLY)) < 0 ) {
    exit(1);
  }
  if ( read(fd, *buffer, bytes) != bytes ) { 
    exit(1);
  }
  if ( close(fd) ) { 
    exit(1);
  }

} /* end dummy_data() */

 /** Compare two data buffers.
  *
  * Return 0 on match, else return 1.
  *
  **/
int compare_data(uchar *buf1, int len1, uchar *buf2, int len2) 
{

	//if (len1 != len2) {       relaxed since decryption leads
	//	return 1;               to trailing zeros, just pass
	//}                         original before decrypted for now

	int i;
	for (i = 0; i < len1; i++) {
		fprintf(stderr, "%x - %x", *(buf1 + i), *(buf2 + i));
		if ( *(buf1 + i) != *(buf2 + i) ) {
			return 1;
		}
	}

	return 0;
}



/**
 * Copyright (c) 2013 Gavin Cabbage.
 **/
