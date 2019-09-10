
/*********************************
 *	This implementation is based on the
 *  public domain "SHA-1 in C" code
 *  by Steve Reid <steve@edmweb.com>
 *********************************/

#include "smfHashSHA1.h"

#include <sys/types.h>  // for BYTE_ORDER macro
#include <string.h>     // for memcpy(), etc
#ifndef WIN32
#include <arpa/inet.h>  // for htonl()
#endif // WIN32 ljt
SmfHashSHA1::SmfHashSHA1()
{
    Init();
}

SmfHashSHA1::~SmfHashSHA1()
{
}

void SmfHashSHA1::Init()
{
    // SHA1 initialization constants
    digest_buffer[0] = 0x67452301;
    digest_buffer[1] = 0xEFCDAB89;
    digest_buffer[2] = 0x98BADCFE;
    digest_buffer[3] = 0x10325476;
    digest_buffer[4] = 0xC3D2E1F0;
    bit_count[0] = bit_count[1] = 0;
}  // end SmfHashSHA1::Init()

void SmfHashSHA1::Update(const char* data, unsigned int len)
{
    unsigned int i = 0;
    unsigned int j = (bit_count[0] >> 3) & 63;
    if ((bit_count[0] += (len << 3)) < ((len << 3))) bit_count[1]++;
    bit_count[1] += (len >> 29);
    if ((j + len) > 63) 
    {
        memcpy(((char*)data_buffer) + j, data, (i = 64-j));
        Transform();
        for (; i + 63 < len; i += 64) 
        {
            memcpy(data_buffer, data+i, 64);
            Transform();
        }
        j = 0;
    }
    else 
    {
        i = 0;
    }
    memcpy(((char*)data_buffer) + j, &data[i], len - i);
}  // end SmfHashSHA1::Update()

void SmfHashSHA1::Finalize()
{
    unsigned char finalcount[8];
    unsigned int i;
    for (i = 0; i < 8; i++) 
    {
        // Endian independent
        finalcount[i] = (unsigned char)((bit_count[(i >= 4 ? 0 : 1)] >> ((3-(i & 3)) * 8) ) & 255);  
    }
    Update((char*)"\200", 1);
    while ((bit_count[0] & 504) != 448)
        Update((char*)"\0", 1);
    Update((char*)finalcount, 8); 
#if BYTE_ORDER == LITTLE_ENDIAN
    for (i = 0; i < 5; i++)
        digest_buffer[i] = htonl(digest_buffer[i]);
#endif // LITTLE_ENDIAN
}  // end SmfHashSHA1::Finalize()

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

// blk0() and blk() perform the initial expand. 
// Steve Reid got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block[i] = (rol(block[i],24) & 0xFF00FF00) | (rol(block[i],8) & 0x00FF00FF))
#else
#define blk0(i) block[i]
#endif  // if/else LITTLE_ENDIAN

#define blk(i) (block[i&15] = rol(block[(i+13)&15]^block[(i+8)&15] \
    ^block[(i+2)&15]^block[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);



#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

// Hash a single 512-bit block. This is the core of the algorithm. 

void SmfHashSHA1::Transform()
{
    UINT32* block = data_buffer;

    // Copy state into working variables
    UINT32 a = digest_buffer[0];
    UINT32 b = digest_buffer[1];
    UINT32 c = digest_buffer[2];
    UINT32 d = digest_buffer[3];
    UINT32 e = digest_buffer[4];
    
    // 4 rounds of 20 operations each. Loop unrolled.
    R0(a,b,c,d,e,0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    // Add the working vars back into digest_buffer
    digest_buffer[0] += a;
    digest_buffer[1] += b;
    digest_buffer[2] += c;
    digest_buffer[3] += d;
    digest_buffer[4] += e;
    
}  // end SmfHashSHA1::Transform()
