#include <stdio.h>
#include<iostream>
#include<conio.h>
using namespace std;
typedef unsigned long uint32_t;  
const uint32_t TEAKey[4] = {0x95a8882c, 0x9d2cc113, 0x815aa0cd, 0xa1c489f7};

void encrypt (uint32_t* v, const uint32_t* k);
void decrypt (uint32_t* v, const uint32_t* k);

void btea(uint32_t *v, int n, uint32_t const k[4]);

void simpleencrypt(unsigned char * buffer);
void simpledecrypt(unsigned char * buffer);

int main()
{
uint32_t teadata[2] = {165482,635698};
uint32_t teaKey[4] = {12341,69852,56254,69885};
uint32_t teadataE[2] = {1579444754,302792064};
//uint32_t teaKey[4] = {12341,69852,56254,69885};
cout<<"orgional data\n";
cout<<teadata[0]<<" "<<teadata[1]<<"\n";
encrypt(teadata,teaKey);
decrypt(teadataE,teaKey);

getch();
   return 0;
}

void simpleencrypt(unsigned char * buffer)
{
    uint32_t datablock[2];

    datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
    datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

    encrypt (datablock, TEAKey);

    buffer[0] = (char) ((datablock[0] >> 24) & 0xFF);
    buffer[1] = (char) ((datablock[0] >> 16) & 0xFF);
    buffer[2] = (char) ((datablock[0] >> 8) & 0xFF);
    buffer[3] = (char) ((datablock[0]) & 0xFF);
    buffer[4] = (char) ((datablock[1] >> 24) & 0xFF);
    buffer[5] = (char) ((datablock[1] >> 16) & 0xFF);
    buffer[6] = (char) ((datablock[1] >> 8) & 0xFF);
    buffer[7] = (char) ((datablock[1]) & 0xFF);
}

void simpledecrypt(unsigned char * buffer)
{
    uint32_t datablock[2];

    datablock[0] = (buffer[0] << 24) | (buffer[1] << 16)  | (buffer[2] << 8) | (buffer[3]);
    datablock[1] = (buffer[4] << 24) | (buffer[5] << 16)  | (buffer[6] << 8) | (buffer[7]);

    decrypt (datablock, TEAKey);

    buffer[0] = (char) ((datablock[0] >> 24) & 0xFF);
    buffer[1] = (char) ((datablock[0] >> 16) & 0xFF);
    buffer[2] = (char) ((datablock[0] >> 8) & 0xFF);
    buffer[3] = (char) ((datablock[0]) & 0xFF);
    buffer[4] = (char) ((datablock[1] >> 24) & 0xFF);
    buffer[5] = (char) ((datablock[1] >> 16) & 0xFF);
    buffer[6] = (char) ((datablock[1] >> 8) & 0xFF);
    buffer[7] = (char) ((datablock[1]) & 0xFF);
}

/* encrypt
 *   Encrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be encoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - encrypted result
 * Side effects:
 *   None
 */
void encrypt (uint32_t* v, const uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
    cout<<"encryption:"<<"\n";
    cout<<v[0]<<" "<<v[1];
    cout<<"\n";
    
}

/* decrypt
 *   Decrypt 64 bits with a 128 bit key using TEA
 *   From http://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
 * Arguments:
 *   v - array of two 32 bit uints to be decoded in place
 *   k - array of four 32 bit uints to act as key
 * Returns:
 *   v - decrypted result
 * Side effects:
 *   None
 */
void decrypt (uint32_t* v, const uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
    cout<<"decryption:"<<"\n";
    cout<<v[0]<<" "<<v[1];
}

#define DELTA 0x9e3779b9
  #define MX ((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (k[(p&3)^e] ^ z));

  void btea(uint32_t *v, int n, uint32_t const k[4]) {
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1) {          /* Coding Part */
      rounds = 6 + 52/n;
      sum = 0;
      z = v[n-1];
      do {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p=0; p<n-1; p++)
          y = v[p+1], z = v[p] += MX;
        y = v[0];
        z = v[n-1] += MX;
      } while (--rounds);
    } else if (n < -1) {  /* Decoding Part */
      n = -n;
      rounds = 6 + 52/n;
      sum = rounds*DELTA;
      y = v[0];
      do {
        e = (sum >> 2) & 3;
        for (p=n-1; p>0; p--)
          z = v[p-1], y = v[p] -= MX;
        z = v[n-1];
        y = v[0] -= MX;
      } while ((sum -= DELTA) != 0);
    }
  }
