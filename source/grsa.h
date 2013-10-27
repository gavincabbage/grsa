/******************************************************************************
 *                                                                            *
 *               grsa - RSA Cryptography Library (header)                     *
 *               Gavin Cabbage - gavincabbage@gmail.com                       *
 *                                                                            *
 ******************************************************************************/



#ifndef GRSA_H
#define GRSA_H



/** Library includes. 
 *
 **/
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <gmp.h>



/** General definitions. 
 *
 **/
#ifndef DEF_E                  /* Default public exponent.                    */
#define DEF_E 65537
#endif
#ifndef DEF_BLOCKSIZE          /* Default blocksize.                          */
#define DEF_BLOCKSIZE 8
#endif
#ifndef MIN_KEYLEN             /* Minimum keylength in bits.                  */
#define MIN_KEYLEN 32
#endif
#ifndef HASH_LEN
#define HASH_LEN 16
#endif
#ifndef HASH_MOD               /* Random hash modulus, HASH_LEN bytes.        */
#define HASH_MOD "8f0a28dd2ad117aeafbc3e21966cd37f"
#endif
#ifndef SIG_BLOCKSIZE          /* Blocksize for signature encryption.         */
#define SIG_BLOCKSIZE 4
#endif 
#ifndef RANDOM
#define RANDOM "/dev/random"
#endif
#ifndef URANDOM
#define URANDOM "/dev/urandom"
#endif
#ifndef ENCODE_NONE            /* No encoding.                                */
#define ENCODE_NONE 0
#endif
#ifndef ENCODE_RANDOM          /* Random encoding                             */
#define ENCODE_RANDOM 1
#endif
#ifndef ENCODE_OAEP            /* OAEP encoding.                              */
#define ENCODE_OAEP 2
#endif
#ifndef CEILING                /* Ceiling of A divided by B. */
#define CEILING(a, b) (a % b == 0) ? a/b : a/b + 1
#endif



/** Standard return codes for all functions.
 *
 * Pass return values to grsa_perror() to display an appropriate
 * success/error message. A positive value indicates an error.
 *
 **/
#ifndef NEGATIVE               /* Successful execution, negative return.      */
#define NEGATIVE -1
#endif
#ifndef POSITIVE               /* Successful execution, positive return.      */
#define POSITIVE 0
#endif
#ifndef ARG_ERR                /* One or more invalid arguments.              */
#define ARG_ERR 1
#endif
#ifndef MEM_ERR                /* Unable to allocate adequate memory.         */
#define MEM_ERR 2
#endif
#ifndef GMP_ERR                /* Error executing GMP function.               */
#define GMP_ERR 3
#endif
#ifndef GRSA_ERR               /* Error executing nested GRSA function.       */
#define GRSA_ERR 4
#endif 
#ifndef NDX_ERR                /* Invalid buffer index or length.             */
#define NDX_ERR 5
#endif
#ifndef RAND_ERR               /* Error during random number generation.      */
#define RAND_ERR 6
#endif



/** [1] DATA STRUCTURES *******************************************************/


 /** GRSA Key.
  *
  **/
typedef struct grsa_key
{
  size_t bytes;                /* Keysize in bytes.           */
  mpz_t modulus;               /* Public modulus.             */
  mpz_t exponent;              /* Public or private exponent. */
} grsa_key;


 /** GRSA Keypair.
  *
  **/
typedef struct grsa_keypair
{
  grsa_key *pub;               /* Public key.  */
  grsa_key *priv;              /* Private key. */
} grsa_keypair;


 /** Use fixed width, unsigned integers for consistency and security.
  *
  **/
typedef uint32_t uint;
typedef uint8_t uchar;



/** [2] KEY GENERATION ********************************************************/


 /** Generate a GRSA Keypair of the given length in bits.
  *
  * Return zero on success, non-zero on error.
  *
  * Note: Memory is allocated for the keypair buffer in this function.
  *
  **/
int grsa_generate_keypair
(
  grsa_keypair **keypair,      /* Pointer to keypair buffer to populate. */
  const mp_bitcnt_t bits,      /* Size of key to be generated in bits.   */
  unsigned long pub_exp        /* Public exponent to be used.            */
);


 /** Verify a GRSA keypair.
  *
  * Return 0 on successful positive key verification, -1 on successful
  * negative key verification, greater than 0 on error.
  *
  **/
int grsa_verify_keypair
(
  const grsa_keypair *keypair  /* Keypair to test. */
);



/** [3] ENCRYPTION & DECRYPTION ***********************************************/


 /** Encrypt a data buffer.
  * 
  * Return 0 on success, non-zero on error.
  *
  * Note: Memory is allocated for the ciphertext buffer in this function!
  *
  **/
int grsa_encrypt
(
  uchar **ciphertext,          /* Pointer to ciphertext buffer to populate. */
  uint *ciphertext_len,        /* Length of computed ciphertext in bytes.   */
  const uchar *plaintext,      /* Plaintext buffer to be encrypted.         */
  const uint plaintext_len,    /* Length of plaintext buffer.               */
  const grsa_key *key,         /* Public key to be used during encryption.  */
  uint encoding,               /* Encoding scheme to use.                   */
  uint blocksize               /* Size of message blocks to be encrypted.   */
);


/** Decrypt an encrypted data buffer.
  *
  * Return 0 on success, non-zero on error.
  *
  * Note: Memory is allocated for the plaintext buffer in this function.
  *
  **/
int grsa_decrypt
(
  uchar **plaintext,           /* Pointer to plaintext buffer to populate. */
  uint *plaintext_len,         /* Length of computed plaintext in bytes.   */
  const uchar *ciphertext,     /* Ciphertext buffer to be decrypted.       */
  const uint ciphertext_len,   /* Length of ciphertext buffer.             */
  const grsa_key *key,         /* Private key to be used for decryption.   */
  uint encoding,               /* Encoding scheme to use.                  */
  uint blocksize               /* Size of message blocks to be decrypted   */
);



/** [4] DIGITAL SIGNING & SIGNATURE VERIFICATION ******************************/


 /** Sign a data buffer.
  *
  * Return 0 on success, non-zero on error.
  *
  * Note: Memory is allocated for the signature buffer in this function.
  *
  **/
int grsa_sign
(
  uchar **signature,           /* Pointer to signature buffer to populate. */
  uint *sig_len,               /* Length of computed signature.            */
  const uchar *data,           /* Data buffer to sign.                     */
  const uint msg_len,          /* Length of data buffer.                   */
  const grsa_key *key          /* Private key used to sign digest.         */
);


 /** Verify a data buffer's signature.
  *
  * Return 0 on successful positive signature verification and -1 on successful
  * negative signature verification. Return greater than 0 on error.
  *
  **/
int grsa_verify
(
  const uchar *signature,      /* Signature buffer to be verified.     */
  const uint sig_len,          /* Length of signature buffer.          */
  const uchar *data,           /* Signed plaintext buffer.             */
  const uint data_len,         /* Length of plaintext buffer.          */
  const grsa_key *key          /* Public key used to verify signature. */
);



/** [5] MISCELLANEOUS *********************************************************/


 /** Export a GRSA key to a data buffer.
  * 
  * Return 0 on success, non-zero on error.
  *
  * Note: Memory is allocated for the export buffer in this function!
  *
  **/
int grsa_export
(
  uchar **buffer,              /* Pointer to buffer to populate.    */
  uint *buffer_len,            /* Length of data written to buffer. */
  const grsa_key *key          /* Key to export.                    */
);


 /** Import a data buffer into a GRSA key.
  * 
  * Return 0 on success, non-zero on error.
  *
  * Note: Memory is allocated for the key buffer in this function.
  *
  **/
int grsa_import
(
  grsa_key **key,              /* Pointer to key structure to populate. */
  const uchar *buffer,         /* Data buffer to import.                */
  const uint buffer_len        /* Length of data buffer.                */
);


 /** Clear a GRSA key structure. 
  *
  **/
void grsa_clrkey
(
  grsa_key *key                /* Key to be cleared. */
);


 /** Clear a GRSA keypair structure.
  *
  **/
void grsa_clrkeypair
(
  grsa_keypair *keypair        /* Keypair to be cleared. */
);


 /** Print a success or error message.
  *
  * Note: This function writes to standard error.
  *
  **/
void grsa_perror
(
  const char *src,             /* Source function.                    */
  const int retval             /* Return value on which to elaborate. */
);



#endif /* GRSA_H */



/**
 * Copyright (c) 2013 Gavin Cabbage.
 **/
