#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <botan/auto_rng.h>
#include <botan/scrypt.h>
#include <botan/keccak.h>
#include <botan/cipher_mode.h>
#include <botan/p11_ecdsa.h>

#include "util.h"

int main()
{
  //#include "thisisatestwallet.h"
  //#include "web3secret.h"
  #include "donotcommit.h"

  //alloc/populate
  uint8_t *saltb = hexs2bytes(salth,strlen(salth));
  size_t saltblen = strlen(salth)/2;
  uint8_t *ciphertextb = hexs2bytes(ciphertexth,strlen(ciphertexth));
  size_t ciphertextblen = strlen(ciphertexth)/2;
  uint8_t *ivb = hexs2bytes(ivh,strlen(ivh));
  size_t ivblen = strlen(ivh)/2;

  size_t cipherinputblen = 16+ciphertextblen;
  uint8_t *cipherinputb = (uint8_t *)malloc(cipherinputblen);
  memset(cipherinputb,0,cipherinputblen);

  size_t wkeyblen = 32;
  uint8_t *wkeyb = (uint8_t *)malloc(wkeyblen);
  memset(wkeyb,0,wkeyblen);

  Botan::Keccak_1600 keccak = Botan::Keccak_1600(256);
  Botan::AutoSeeded_RNG rng{};

  //derive wkey
  Botan::scrypt(
    wkeyb, wkeyblen,
    passc, strlen(passc),
    saltb, saltblen,
    kdf_n, kdf_r, kdf_p);

  printPad("wkey:");
  printBytes(wkeyb,wkeyblen);

  printPad("ciphertext:");
  for(size_t i = 0; i < 64; i++) printf(" "); //to align w/ cipherinput
  printHexNormalized(ciphertexth);

  //concatenate
  memcpy(cipherinputb,    wkeyb+16,    16);
  memcpy(cipherinputb+16, ciphertextb, ciphertextblen);
  printPad("cipher input:");
  for(size_t i = 0; i < 32; i++) printf(" "); //to align w/ cipherinput
  printBytes(cipherinputb,cipherinputblen);

  //hash
  keccak.clear();
  Botan::secure_vector<uint8_t> macb = keccak.process(cipherinputb,cipherinputblen);
  printPad("keccak out:");
  printBytes(macb.data(),macb.size());

  //should match mac
  printPad("mac (matches ^):");
  printHexNormalized(mach);

  //decrypt private key
  std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-128/CTR", Botan::ENCRYPTION);
  enc->set_key(wkeyb,16);
  enc->start(ivb,ivblen);
  Botan::secure_vector<uint8_t> cipherresultb(ciphertextblen);
  cipherresultb.assign(ciphertextb,ciphertextb+ciphertextblen);
  enc->finish(cipherresultb);
  printPad("pkey:");
  printBytes(cipherresultb.data(),cipherresultb.size());

  //generate public key

  Botan::BigInt pkeyint = Botan::BigInt(cipherresultb);
  Botan::ECDSA_PrivateKey pkey = Botan::ECDSA_PrivateKey(rng,Botan::EC_Group("secp256k1"),pkeyint);
  printPad("pubkey:");
  std::vector<uint8_t> pubkeyb = pkey.public_key_bits();
  pubkeyb.erase(pubkeyb.begin(),pubkeyb.begin()+1); //quirk of botan pub keygen?
  printBytes(pubkeyb.data(),pubkeyb.size());

  //generate address
  keccak.clear();
  Botan::secure_vector<uint8_t> addr = keccak.process(pubkeyb.data(),pubkeyb.size());
  printPad("keccak out:");
  printBytes(addr.data(),addr.size());
  printPad("address:");
  printBytes(addr.data()+addr.size()-20,20);

  free(wkeyb);
  free(cipherinputb);
  free(ivb);
  free(ciphertextb);
  free(saltb);
}
