#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <botan/scrypt.h>
#include <botan/keccak.h>

#include "util.h"

int main()
{
  //*
  //thisisatestwallet.json
  const char *ciphertexth = "c6d18f78af6e5e7cea4ab804d8b9a5f974ccf92ea2537416b90abebd77c6b580";
  const char *salth = "d77fe79c1162d34e85994a338e815d3904c171c67cc3f72d4b433aa19dbc7bb1";
  const char *passc = "thisisatestwallet";
  const char *mach = "89655fd4bb9ccf9de0d8f1a78025a8616c9416ec700cfaafef17e76c7c47338e";
  size_t kdf_n = 262144;
  size_t kdf_r = 8;
  size_t kdf_p = 1;
  //*/

  /*
  //web3 test wallet
  const char *ciphertexth = "d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c";
  const char *salth = "ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19";
  const char *passc = "testpassword";
  const char *mach = "2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097";
  size_t kdf_n = 262144;
  size_t kdf_r = 1;
  size_t kdf_p = 8;
  //*/

  //alloc/populate
  uint8_t *saltb = hexs2bytes(salth,strlen(salth));
  size_t saltblen = strlen(salth)/2;
  uint8_t *ciphertextb = hexs2bytes(ciphertexth,strlen(ciphertexth));
  size_t ciphertextblen = strlen(ciphertexth)/2;
  size_t cipherinputblen = 16+ciphertextblen;
  uint8_t *cipherinputb = (uint8_t *)malloc(cipherinputblen);
  memset(cipherinputb,0,cipherinputblen);
  size_t pkeyblen = 32;
  uint8_t *pkeyb = (uint8_t *)malloc(pkeyblen);
  memset(pkeyb,0,pkeyblen);

  //derive pkey
  Botan::scrypt(
    pkeyb, pkeyblen,
    passc, strlen(passc),
    saltb, saltblen,
    kdf_n, kdf_r, kdf_p);

  printPad("pkey:");
  printBytes(pkeyb,pkeyblen);

  printPad("ciphertext:");
  for(size_t i = 0; i < 64; i++) printf(" "); //to align w/ cipherinput
  printHexNormalized(ciphertexth);

  //concatenate
  memcpy(cipherinputb,    pkeyb+16,    16);
  memcpy(cipherinputb+16, ciphertextb, ciphertextblen);
  printPad("cipher input:");
  for(size_t i = 0; i < 32; i++) printf(" "); //to align w/ cipherinput
  printBytes(cipherinputb,cipherinputblen);

  //hash
  Botan::Keccak_1600 keccak = Botan::Keccak_1600(256);
  Botan::secure_vector<uint8_t> keccak_out = keccak.process(cipherinputb,cipherinputblen);
  printPad("keccak out:");
  printBytes(keccak_out.data(),keccak_out.size());

  printPad("mac:");
  printHexNormalized(mach);

  free(ciphertextb);
  free(saltb);
}
