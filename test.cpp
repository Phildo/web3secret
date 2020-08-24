#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <botan/scrypt.h>
#include <botan/sha3.h>

uint8_t hex2nybbl(char h)
{
  switch(h)
  {
    case '0': return            0; break;
    case '1': return            1; break;
    case '2': return            2; break;
    case '3': return            3; break;
    case '4': return            4; break;
    case '5': return            5; break;
    case '6': return            6; break;
    case '7': return            7; break;
    case '8': return            8; break;
    case '9': return            9; break;
    case 'A': case 'a': return 10; break;
    case 'B': case 'b': return 11; break;
    case 'C': case 'c': return 12; break;
    case 'D': case 'd': return 13; break;
    case 'E': case 'e': return 14; break;
    case 'F': case 'f': return 15; break;
  }
  assert(0);
  return 0;
}

char nybbl2hex(uint8_t n)
{
  switch(n)
  {
    case  0: return '0'; break;
    case  1: return '1'; break;
    case  2: return '2'; break;
    case  3: return '3'; break;
    case  4: return '4'; break;
    case  5: return '5'; break;
    case  6: return '6'; break;
    case  7: return '7'; break;
    case  8: return '8'; break;
    case  9: return '9'; break;
    case 10: return 'A'; break;
    case 11: return 'B'; break;
    case 12: return 'C'; break;
    case 13: return 'D'; break;
    case 14: return 'E'; break;
    case 15: return 'F'; break;
  }
  assert(0);
  return 0;
}

uint8_t hex2byte(const char *h)
{
  uint8_t b{};
  b = hex2nybbl(h[0])<<4 | hex2nybbl(h[1]);
  return b;
}

void byte2hex(uint8_t b, char *h)
{
  h[0] = nybbl2hex(b >> 4);
  h[1] = nybbl2hex(b & 0xF);
}

uint8_t *hexs2bytes(const char *h, size_t len)
{
  uint8_t *b = (uint8_t *)malloc(len/2);
  for(size_t i = 0; i < len/2; i++)
    b[i] = hex2byte(&h[i*2]);
  return b;
}

char *bytes2hexs(const uint8_t *b, size_t len)
{
  char *h = (char *)malloc(len*2+1);
  for(size_t i = 0; i < len; i++)
    byte2hex(b[i],&h[i*2]);
  h[len*2] = '\0';
  return h;
}

void printBytes(const uint8_t *b, size_t len)
{
  char *h = bytes2hexs(b,len);
  printf("%s\n",h);
  free(h);
}

void printHexNormalized(const char *h)
{
  uint8_t *b = hexs2bytes(h,strlen(h));
  char *nh = bytes2hexs(b,strlen(h)/2);
  printf("%s\n",nh);
  free(nh);
  free(b);
}

int main()
{
  const char *ciphertexth = "c6d18f78af6e5e7cea4ab804d8b9a5f974ccf92ea2537416b90abebd77c6b580";
  const char *salth = "d77fe79c1162d34e85994a338e815d3904c171c67cc3f72d4b433aa19dbc7bb1";
  const char *passc = "thisisatestwallet";
  const char *mach = "89655fd4bb9ccf9de0d8f1a78025a8616c9416ec700cfaafef17e76c7c47338e";

  //alloc/populate
  uint8_t *saltb = hexs2bytes(salth,strlen(salth));
  size_t saltblen = strlen(salth)/2;
  uint8_t*ciphertextb = hexs2bytes(ciphertexth,strlen(ciphertexth));
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
    262144, 8, 1);
  printf("pkey:\n");
  printBytes(pkeyb,pkeyblen);

  printf("ciphertext:\n");
  for(size_t i = 0; i < 64; i++) printf(" "); //to align w/ cipherinput
  printHexNormalized(ciphertexth);

  //concatenate
  memcpy(cipherinputb,              pkeyb+16,   pkeyblen-16);
  memcpy(cipherinputb+(pkeyblen-16),ciphertextb,ciphertextblen);
  printf("cipher input:\n");
  for(size_t i = 0; i < 32; i++) printf(" "); //to align w/ cipherinput
  printBytes(cipherinputb,cipherinputblen);

  //hash
  Botan::SHA_3_256 keccak{};
  Botan::secure_vector<uint8_t> keccak_out = keccak.process(cipherinputb,cipherinputblen);;
  printf("keccak out:\n");
  printBytes(keccak_out.data(),keccak_out.size());

  printf("mac:\n");
  printHexNormalized(mach);

  free(ciphertextb);
  free(saltb);
}
