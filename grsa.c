/******************************************************************************
 *                                                                            *
 *               grsa - RSA Cryptography Library (implementation)             *
 *               Gavin Cabbage - gavincabbage@gmail.com                       *
 *                                                                            *
 ******************************************************************************/



#include "grsa.h"



/** [1] IMPLEMENTATION HELPERS ************************************************/
 

 /** Generate a random GMP integer. 
  *
  * The resulting integer will be of the given length in bits. The most
  * most significant bit is guaranteed to be set, yielding a range of
  * 2^(bits-1) to (2^bits)-1 inclusive.
  *
  **/
int _gen_random ( mpz_t random, mp_bitcnt_t bits )
{

  /* Read seed bits from random device. 
   */
  int fd; int bytes = bits/8;
  uchar seed_buffer[bytes];
  if ( (fd = open(URANDOM, O_RDONLY)) < 0 ) {
    return ARG_ERR;
  }
  if ( read(fd, seed_buffer, bytes) != bytes ) { 
    return ARG_ERR;
  }
  if ( close(fd) ) { 
    return ARG_ERR;
  }

  /* Import random bits into GMP integer. 
   */
  mpz_t seed;
  mpz_init(seed);
  mpz_import(seed, bytes, 1, 1, 0, 0, seed_buffer);

  /* Initialize and seed GMP random state. 
   */
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed(state, seed);
  mpz_clear(seed);

  /* Generate a random number of given number of bits 
   * and set most significant bit.
   */
  mpz_urandomb(random, state, bits);
  mpz_setbit(random, bits-1); 

  gmp_randclear(state);
  return POSITIVE;

} /* end _gen_random() */


 /** Generate two random primes.
  * 
  * The primes will be of the given length in bits. Both are guaranteed
  * to be unique, within the range of 2^(bits-1) to (2^bits)-1 inclusive and
  * relatively prime to the given public exponent.
  *
  **/
int _gen_primes ( mpz_t prime1, mpz_t prime2, mp_bitcnt_t bits, 
                  unsigned long pub_exp ) 
{

  /* Check that public exponent is not zero.
   */
  if (pub_exp == 0) {
    return ARG_ERR;
  }

  /* Initialize max to (2^bits)-1, modulus result variables to 0. 
   */
  mpz_t max, mod1, mod2;
  mpz_inits(max, mod1, mod2, NULL);
  mpz_setbit(max, bits);
  mpz_sub_ui(max, max, 1); 

  /* Generate primes, asserting each is unique, within range and compatible
   * with the given public exponent. 
   */
  while ( (mpz_cmp(prime1, prime2) == 0)            ||
          (mpz_cmp(prime1, max) > 0)                || 
          (mpz_cmp(prime2, max) > 0)                || 
          (mpz_mod_ui(mod1, prime1, pub_exp) == 1 ) ||
          (mpz_mod_ui(mod2, prime2, pub_exp) == 1 )  )
  {
    if ( (_gen_random(prime1, bits) != 0) ||
         (_gen_random(prime2, bits) != 0)  )
    {
      return RAND_ERR;
    }
    mpz_nextprime(prime1, prime1);
    mpz_nextprime(prime2, prime2);
  }

  mpz_clears(max, mod1, mod2, NULL);
  return POSITIVE;

} /* end _gen_primes() */


 /** Compute a hash value.
  * 
  * Calculate the hash value of a data buffer using an iterated version of 
  * the Knuth variant on the division method, such that h(k) = k*(k+3) mod m, 
  * m = HASH_MOD of length HASH_LEN bytes, as defined in the header file.
  *
  **/
int _hash ( uchar **hash, const uchar *data, const uint data_len )
{

  /* Validate arguments. 
   */
  if (data == NULL) {
    return ARG_ERR;
  }

  /* Allocate memory for hash result. 
   */
  if ( (*hash = malloc(HASH_LEN)) == NULL ) { 
    return MEM_ERR; 
  }

  /* Initialize data array and copy data from original buffer. 
   */
  uint num_blocks = CEILING(data_len, HASH_LEN);
  uint padded_len = num_blocks * HASH_LEN;
  char data_cpy[padded_len];
  memset(data_cpy, 0, padded_len);  /* Pad with zero bytes. */
  memcpy(data_cpy, data, data_len); /* Copy in data.        */

  /* Initialize working GMP integers for hash process. 
   */
  mpz_t hash_res, hash_block, hash_add, hash_mod;
  mpz_inits(hash_res, hash_block, hash_add, hash_mod, NULL);
  mpz_set_str(hash_mod, HASH_MOD, 16);

  /* Iterate across data in blocks of HASH_LEN bytes.
   */
  uint i;
  for (i = 0; i < padded_len; i += HASH_LEN) 
  {
    /*  Import data block into GMP integer. */
    mpz_import(hash_block, HASH_LEN, 1, 1, 0, 0, data_cpy+i); // (k)

    /* Hash data block. */
    mpz_add_ui(hash_add, hash_block, 3); /* (k+3) */
    mpz_mul(hash_block, hash_block, hash_add);
    mpz_mod(hash_block, hash_block, hash_mod);

    /* XOR data representation into working hash. */
    if (i == 0) {
      mpz_set(hash_res, hash_block);           /* Set on first iteration. */
    } else { 
      mpz_xor(hash_res, hash_res, hash_block); /* XOR otherwise.          */
    }

  } /* end for */

  /* Export working integer to hash buffer and null terminate. 
   */
  mpz_export(*hash, NULL, 1, 1, 0, 0, hash_res);

  mpz_clears(hash_res, hash_block, hash_add, hash_mod, NULL);
  return POSITIVE;

} /* end _hash() */



/** [2] KEY GENERATION ********************************************************/


 /** Generate a GRSA Keypair of the given length in bits. 
  *
  **/
int grsa_generate_keypair ( grsa_keypair **keypair, const mp_bitcnt_t bitlen, 
                            unsigned long pub_exp ) 
{

  /* Keylength must be a multiple of eight for byte alignment and greater
   * than or equal to MIN_KEYLEN.
   */
  if ( (bitlen % 8 != 0) || (bitlen < MIN_KEYLEN) ) {
    return ARG_ERR;
  }
  
  /* Allocate memory for keypair and key structures.
   */
  if ( ( *keypair = malloc(sizeof(grsa_keypair))) == NULL     ||
       ( (*keypair)->pub = malloc(sizeof(grsa_key))) == NULL  ||
       ( (*keypair)->priv = malloc(sizeof(grsa_key))) == NULL  )
  {
    return MEM_ERR;
  }
  
  /* Initialize key member GMP integers and set length. 
   */
  mpz_inits( (*keypair)->pub->modulus, (*keypair)->pub->exponent,
             (*keypair)->priv->modulus, (*keypair)->priv->exponent, NULL );
  (*keypair)->pub->bytes = (*keypair)->priv->bytes = bitlen / 8;

  /* Initialize working GMP integers.
   */
  mp_bitcnt_t prime_bitlen = bitlen / 2;
  mpz_t prime1, prime2, modulus, phi;
  mpz_inits(prime1, prime2, modulus, phi, NULL);

  /* Generate keypair. Retry if the calculated key is invalid.
   */
  int valid = 0;
  while (!valid)
  {
    /* Set public exponent. Use default if 0 is passed.
     */
    if (pub_exp == 0) {
      pub_exp = DEF_E;
    }
    mpz_set_ui( (*keypair)->pub->exponent, pub_exp );

    /* Generate two primes.
     */
    _gen_primes(prime1, prime2, prime_bitlen, pub_exp);

    /* Calculate modulus and totient result phi. 
     */
    mpz_mul(modulus, prime1, prime2); /* modulus = p1 * p2 */
    mpz_set( (*keypair)->pub->modulus, modulus );
    mpz_set( (*keypair)->priv->modulus, modulus );
    mpz_sub_ui(prime1, prime1, 1);
    mpz_sub_ui(prime2, prime2, 1);
    mpz_mul(phi, prime1, prime2); /* phi = (p1-1) * (p2-1) */

    /* Calculate and set private exponent. 
     */
    if ( mpz_invert( (*keypair)->priv->exponent, 
                     (*keypair)->pub->exponent, phi ) == 0 )
    {
      return GMP_ERR;
    }

    /* Check key for keypair validity. 
     */
    if ( grsa_verify_keypair(*keypair) == 0 ) {
      valid = 1;
    } else {
      valid = 0;
    }

  } /* end while */

  mpz_clears(prime1, prime2, modulus, phi, NULL);
  return POSITIVE;

} /* end grsa_generate_keypair() */


 /** Verify a GRSA keypair.
  * 
  **/
int grsa_verify_keypair ( const grsa_keypair *keypair ) 
{
  /* Verify that keypair is initialized. 
   */
  if (keypair == NULL) {
    return ARG_ERR;
  } 

  /* Generate a random GMP integer less than the given keypair's modulus
   * to act as a dummy message.
   */
  mpz_t message;
  mpz_init(message);
  _gen_random(message, (8*keypair->pub->bytes) - 1);

  /* Encrypt dummy message.
   */
  mpz_t cipher;
  mpz_init(cipher);
  mpz_powm(cipher, message, keypair->pub->exponent, keypair->pub->modulus);

  /* Decrypt dummy message.
   */
  mpz_t decrypted;
  mpz_init(decrypted);
  mpz_powm(decrypted, cipher, keypair->priv->exponent, keypair->priv->modulus);;

  /* Verify that original and decrypted data is identical.
   */
  int result = mpz_cmp(message, decrypted);
  mpz_clears(message, cipher, decrypted, NULL);

  if (result) return NEGATIVE;
  else return POSITIVE;

} /* end grsa_verify_keypair() */



/** [3] ENCRYPTION & DECRYPTION ***********************************************/


 /** Encrypt a data buffer.
  * 
  **/
int grsa_encrypt ( uchar **ciphertext, uint *ciphertext_len, 
                   const uchar *plaintext, const uint plaintext_len, 
                   const grsa_key *key, uint encoding, uint blocksize ) 
{

  /* Process arguments.
   */
  if (plaintext == NULL) {
    return ARG_ERR;
  }
  if (key == NULL) { 
    return ARG_ERR;
  }
  if ( (encoding != ENCODE_NONE)   && 
       (encoding != ENCODE_RANDOM) &&
       (encoding != ENCODE_OAEP)    )
  { 
    return ARG_ERR;
  }

  /* Check blocksize.
   */
  uint max_blocksize = key->bytes - 1;
  if (blocksize > max_blocksize) {
    return NDX_ERR;
  } else if (blocksize == 0) { 
    blocksize = DEF_BLOCKSIZE;
  }

  /* Compute ciphertext length.
   */
  uint num_blocks = CEILING(plaintext_len, blocksize); // | a / b "|
  uint ciphertext_blocksize = key->bytes; // depends on key length
  uint padsize = ciphertext_blocksize - blocksize; // depends on given blocksize
  *ciphertext_len = num_blocks * ciphertext_blocksize;

  /* Allocate memory for ciphertext and working block.
   */
  *ciphertext = NULL;
  if ( (*ciphertext = (uchar *) malloc(*ciphertext_len)) == NULL ) {
    return MEM_ERR; 
  }
  uchar *block;
  if ( (block = (uchar *) malloc(ciphertext_blocksize)) == NULL ) { 
    return MEM_ERR; 
  }   

  /* Iterate across plaintext according to blocksize.
   */ 
  uint ndx; 
  uint cipher_ndx = 0; 
  for (ndx = 0; ndx < plaintext_len; ndx += blocksize) 
  {
    /* Encode initial padsize bytes according to given scheme, if any. */
    memset(block, 0, ciphertext_blocksize); /* Clear working block. */
    if (encoding == ENCODE_RANDOM) {
      /* Initialize GMP integer. */
      mpz_t padding;
      mpz_init(padding);
      uint pad_bits = padsize * 8;
      if ( _gen_random(padding, pad_bits) != 0 ) {
        return RAND_ERR;
      }
      /* Export random integer to working block and clean up. */
      mpz_export(block, NULL, 1, 1, 0, 0, padding);
      mpz_clear(padding);
    } else if (encoding == ENCODE_OAEP) {
      /* OAEP encoding. NOT YET IMPLEMENTED! */
      return ARG_ERR; 
    }

    /* Load plaintext into working block and import into GMP integer. */
    if ( blocksize > (plaintext_len-ndx) ) {  /* In case of partial block */ 
      blocksize = (plaintext_len - ndx);      /* at end of plaintext.     */
    }
    memcpy(block+padsize, plaintext+ndx, blocksize);
    mpz_t block_rep; 
    mpz_init(block_rep);
    mpz_import(block_rep, ciphertext_blocksize, 1, 1, 0, 0, block);

    /* Encrypt block representation with given public key. */
    mpz_t cipher_rep;
    mpz_init(cipher_rep);
    mpz_powm(cipher_rep, block_rep, key->exponent, key->modulus);
    mpz_clear(block_rep);

    /* Export GMP integer to ciphertext. */
    mpz_export(*ciphertext+cipher_ndx, NULL, 1, 1, 0, 0, cipher_rep);
    mpz_clear(cipher_rep);
    cipher_ndx += ciphertext_blocksize;

  } /* end for */

  free(block);
  return POSITIVE;

} /* end grsa_encrypt() */


 /** Decrypt an encrypted data buffer. 
  *
  **/
int grsa_decrypt ( uchar **plaintext, uint *plaintext_len, 
                   const uchar *ciphertext, const uint ciphertext_len, 
                   const grsa_key *key, uint encoding, uint blocksize ) 
{

  /* Process arguments.
   */
  if (ciphertext == NULL) {
    return ARG_ERR;
  }
  if (ciphertext_len % key->bytes != 0) { 
    return ARG_ERR;
  }
  if (key == NULL) { 
    return ARG_ERR;
  }
  if ( (encoding != ENCODE_NONE)   && 
       (encoding != ENCODE_RANDOM) &&
       (encoding != ENCODE_OAEP)    ) 
  {
    return ARG_ERR;
  }

  /* Set blocksize.
   */
  uint max_blocksize = key->bytes - 1;
  if (blocksize > max_blocksize) { 
    return NDX_ERR;
  } else if (blocksize == 0) {
    blocksize = DEF_BLOCKSIZE;
  }

  /* Compute plaintext length.
   */
  uint ciphertext_blocksize = key->bytes;
  uint num_blocks = CEILING(ciphertext_len, ciphertext_blocksize);
  *plaintext_len = num_blocks * blocksize;

  /* Allocate memory for plaintext and working block.
   */
  *plaintext = NULL;
  if ( (*plaintext = (uchar *) malloc(*plaintext_len) ) == NULL ) { 
    return MEM_ERR; 
  }
  uchar *block;
  if ( (block = (uchar *) malloc(ciphertext_blocksize)) == NULL ) {
    return MEM_ERR;
  } 

  /* Iterate across ciphertext according to ciphertext blocksize.
   */
  uint ndx;
  uint plain_ndx = 0;
  for (ndx = 0; ndx < ciphertext_len; ndx += ciphertext_blocksize) 
  {
    /* Load ciphertext into into working block and import into GMP integer. */
    memset(block, 0, ciphertext_blocksize);
    memcpy(block, ciphertext+ndx, ciphertext_blocksize);
    mpz_t block_rep;
    mpz_init(block_rep);
    mpz_import(block_rep, ciphertext_blocksize, 1, 1, 0, 0, block);

    /* Decrypt ciphertext block with given private key. */
    mpz_t plaintext_rep;
    mpz_init(plaintext_rep);
    mpz_powm(plaintext_rep, block_rep, key->exponent, key->modulus);
    mpz_clear(block_rep);

    /* Export decrypted block to plaintext buffer. */
    mpz_export(block, NULL, 1, 1, 0, 0, plaintext_rep);
    mpz_clear(plaintext_rep);

    /* Because only the least significant blocksize bytes of the decrypted
     * block are actual plaintext data, no decoding is necessary.
     */

    /* Write least significant blocksize bytes to plaintext buffer. */
    strncpy((char*)*plaintext+plain_ndx, (char*)block, blocksize);
    plain_ndx += blocksize;

  } /* end for */

  free(block);
  return POSITIVE;

} /* end grsa_decrypt() */
 


/** [4] DIGITAL SIGNING & SIGNATURE VERIFICATION ******************************/


 /** Sign a data buffer. 
  * 
  **/
int grsa_sign ( uchar **signature, uint *sig_len, const uchar *data, 
                const uint data_len, const grsa_key *key ) 
{

  /* Process arguments.
   */
  if (data == NULL) {
    return ARG_ERR;
  }
  if (key == NULL) { 
    return ARG_ERR;
  }

  /* Hash data to create data digest, HASH_LEN bytes allocated. 
   */
  uchar *digest = NULL;
  if (_hash(&digest, data, data_len) != 0) {
    return GRSA_ERR;
  }

  /* Calculate buffer size.
   */
  uint num_blocks = CEILING(HASH_LEN, SIG_BLOCKSIZE);
  *sig_len = num_blocks * key->bytes;

  /* Encrypt digest with given private key.
   */
  uint retlen;
  if (grsa_encrypt(signature, &retlen, digest, HASH_LEN, key,
      ENCODE_NONE, SIG_BLOCKSIZE) != 0) 
  {
    return GRSA_ERR;
  }
  if (retlen != *sig_len) {  /* Check returned length. */
    return NDX_ERR;
  }

  free(digest);
  return POSITIVE;

} /* end grsa_sign() */


 /** Verify a data buffer's signature. 
  *
  **/
int grsa_verify ( const uchar *signature, const uint sig_len, 
                  const uchar *data, const uint data_len, 
                  const grsa_key *key ) 
{
  
  /* Process arguments and calculate buffer sizes.
   */
  if (signature == NULL) {
    return ARG_ERR;
  }
  if (data == NULL) { 
    return ARG_ERR;
  }
  if (key == NULL) { 
    return ARG_ERR;
  }

  /* Decrypt given signature, yielding original data digest.
   */
  uint decrypted_len;
  uchar *decrypted_digest = NULL;
  if (grsa_decrypt(&decrypted_digest, &decrypted_len, signature, sig_len, 
  		             key, ENCODE_NONE, SIG_BLOCKSIZE) != 0) 
  {
    return GRSA_ERR;
  }

  /* Hash data buffer to compute data digest independently.
   */
  uchar *new_digest;
	if (_hash(&new_digest, data, data_len) != 0) {
    return GRSA_ERR;
  }

  /* Compare digests.
   */
	uint retval = 0;
	uint ndx;
	for (ndx = 0; ndx < HASH_LEN; ndx++) {
		uchar b1 = *(decrypted_digest+ndx);
		uchar b2 = *(new_digest+ndx);
		if (b1 != b2) {
			retval = 1; 
      break; 
    }
	}

  free(decrypted_digest);
  free(new_digest);

  if (retval) return NEGATIVE;
  else return POSITIVE;

} /* end grsa_verify() */



/** [5] MISCELLANEOUS *********************************************************/


 /** Export a GRSA key to a buffer.
  *
  **/
int grsa_export ( uchar **buffer, uint *buffer_len, const grsa_key *key )
{

  /* Process arguments and calculate required buffer length.
   */
  if (key == NULL) {
    return ARG_ERR;
  }
 *buffer_len = (2*key->bytes) + sizeof(key->bytes);

  /* Allocate memory for buffer.
   */
  if ( (*buffer = (uchar*) malloc(*buffer_len)) == NULL ) {
    return MEM_ERR;
  }

  /* Clear buffer and write keysize.
   */
  memset(*buffer, 0, *buffer_len);
  memcpy(*buffer, &key->bytes, sizeof(key->bytes));

  /* Check modulus length and export to buffer.
   */
  if ( mpz_sizeinbase(key->modulus, 2) > (key->bytes*8) ) {
    return NDX_ERR;
  }
  uint ndx = sizeof(key->bytes);
  mpz_export( (*buffer)+ndx, NULL, 1, 1, 0, 0, key->modulus);

  /* Check exponent length and export to buffer.
   */
  if ( mpz_sizeinbase(key->exponent, 2) > (key->bytes*8) ) {
    return NDX_ERR;
  }
  size_t exp_len = CEILING(mpz_sizeinbase(key->exponent, 2), 8);
  ndx += (2*key->bytes) - exp_len;
  mpz_export( (*buffer)+ndx, NULL, 1, 1, 0, 0, key->exponent);

  return POSITIVE;

} /* end grsa_export() */


 /** Import a GRSA key from a buffer.
  *
  **/
int grsa_import ( grsa_key **key, const uchar *buffer, const uint buffer_len )
{

  /* Process arguments.
   */
  if (buffer == NULL ) {
    return ARG_ERR;
  }

  /* Allocate memory and build key structure.
   */
  if ( (*key = (grsa_key*) malloc(sizeof(grsa_key))) == NULL ) {
    return MEM_ERR;
  }
  mpz_inits( (*key)->modulus, (*key)->exponent, NULL );

  /* Copy keysize from buffer.
   */
  memcpy( &(*key)->bytes, buffer, sizeof((*key)->bytes) );

  /* Import modulus from buffer after initialization.
   */
  uint ndx = sizeof((*key)->bytes);
  if (ndx > buffer_len) {
    return NDX_ERR;
  }
  mpz_import( (*key)->modulus, (*key)->bytes, 1, 1, 0, 0, buffer+ndx );

  /* Import exponent from buffer after initialization.
   */
  ndx += (*key)->bytes;
  if (ndx > buffer_len) {
    return NDX_ERR;
  }
  mpz_import( (*key)->exponent, (*key)->bytes, 1, 1, 0, 0, buffer+ndx );

  return POSITIVE;

} /* end grsa_import() */


 /** Clear a GRSA key structure. 
  *
  **/
void grsa_clrkey ( grsa_key *key ) 
{
  mpz_clears(key->modulus, key->exponent, NULL);
  free(key);
}


 /** Clear a GRSA keypair structure.
  *
  **/
void grsa_clrkeypair ( grsa_keypair *keypair ) 
{
  grsa_clrkey(keypair->pub);
  grsa_clrkey(keypair->priv);
  free(keypair);
}


 /** Print a success or error message based on the given GRSA return value.
  *
  **/
void grsa_perror ( const char *src, const int retval )
{ 

  /* Print message conditional on retval. 
   */
  if (retval == 0) {
    fprintf(stderr, "[%s] success: positive result.\n", src);
  } else if (retval == -1) {
    fprintf(stderr, "[%s] success: negative result.\n", src);
  } else {
    fprintf(stderr, "[%s] error %d: ", src, retval);
    switch(retval)
    {
    case ARG_ERR:
      fprintf(stderr, "one or more invalid arguments.\n"); 
      break;
    case MEM_ERR:
      fprintf(stderr, "unable to allocate adequate memory.\n"); 
      break;
    case GMP_ERR:
      fprintf(stderr, "error executing GMP function.\n"); 
      break;
    case GRSA_ERR:
      fprintf(stderr, "error executing nested GRSA function.\n"); 
      break;
    case NDX_ERR:
      fprintf(stderr, "invalid buffer index or length.\n");
      break;
    case RAND_ERR:
      fprintf(stderr, "error during random number generation.\n"); 
      break;
    default:
      fprintf(stderr, "undefined error.\n");
      break;
    }
  }

} /* end grsa_perror() */



/**
 * Copyright (c) 2013 Gavin Cabbage.
 **/
 