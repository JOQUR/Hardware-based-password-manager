/*
  Diffie-Hellman key exchange (without HMAC) aka ECDH_anon in RFC4492


  1. Alice picks a (secret) random natural number 'a', calculates P = a * G and sends P to Bob.
     'a' is Alice's private key. 
     'P' is Alice's public key.

  2. Bob picks a (secret) random natural number 'b', calculates Q = b * G and sends Q to Alice.
     'b' is Bob's private key.
     'Q' is Bob's public key.

  3. Alice calculates S = a * Q = a * (b * G).

  4. Bob calculates T = b * P = b * (a * G).

  .. which are the same two values since multiplication in the field is commutative and associative.

  T = S = the new shared secret.


  Pseudo-random number generator inspired / stolen from: http://burtleburtle.net/bob/rand/smallprng.html

*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ecdh.h"










/* WARNING: This is not working correctly. ECDSA is not working... */
void ecdsa_broken()
{
  static uint8_t  prv[ECC_PRV_KEY_SIZE];
  static uint8_t  pub[ECC_PUB_KEY_SIZE];
  static uint8_t  msg[ECC_PRV_KEY_SIZE];
  static uint8_t  signature[ECC_PUB_KEY_SIZE];
  static uint8_t  k[ECC_PRV_KEY_SIZE];
  uint32_t i;

  srand(time(0));
  srand(42);

  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
  {
    prv[i] = rand();
    msg[i] = prv[i] ^ rand();
    k[i] = rand();
  }

/* int ecdsa_sign(const uint8_t* private, const uint8_t* hash, uint8_t* random_k, uint8_t* signature);
   int ecdsa_verify(const uint8_t* public, const uint8_t* hash, uint8_t* signature);                          */

  ecdh_generate_keys(pub, prv);
  /* No asserts - ECDSA functionality is broken... */
  ecdsa_sign((const uint8_t*)prv, msg, k, signature);
  ecdsa_verify((const uint8_t*)pub, msg, (const uint8_t*)signature); /* fails... */
}