#pragma once

#include <cstdint>
#include <cstdio>
#include <cassert>

inline uint8_t hex2nybbl(char h)
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

inline char nybbl2hex(uint8_t n)
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

inline uint8_t hex2byte(const char *h)
{
  uint8_t b{};
  b = hex2nybbl(h[0])<<4 | hex2nybbl(h[1]);
  return b;
}

inline void byte2hex(uint8_t b, char *h)
{
  h[0] = nybbl2hex(b >> 4);
  h[1] = nybbl2hex(b & 0xF);
}

inline uint8_t *hexs2bytes(const char *h, size_t len)
{
  uint8_t *b = (uint8_t *)malloc(len/2);
  for(size_t i = 0; i < len/2; i++)
    b[i] = hex2byte(&h[i*2]);
  return b;
}

inline char *bytes2hexs(const uint8_t *b, size_t len)
{
  char *h = (char *)malloc(len*2+1);
  for(size_t i = 0; i < len; i++)
    byte2hex(b[i],&h[i*2]);
  h[len*2] = '\0';
  return h;
}

inline void printBytes(const uint8_t *b, size_t len)
{
  char *h = bytes2hexs(b,len);
  printf("%s\n",h);
  free(h);
}

inline void printHexNormalized(const char *h)
{
  uint8_t *b = hexs2bytes(h,strlen(h));
  char *nh = bytes2hexs(b,strlen(h)/2);
  printf("%s\n",nh);
  free(nh);
  free(b);
}

inline void printPad(const char *str)
{
  printf("%s",str);
  size_t l = strlen(str);
  while(l < 16) { printf(" "); l++; }
}
