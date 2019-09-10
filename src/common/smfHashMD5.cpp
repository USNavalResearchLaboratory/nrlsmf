#include "smfHashMD5.h"

#include <sys/types.h>  // for BYTE_ORDER macro
#include <string.h>  // for memcpy(), etc

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.	This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare 
 * an SmfHashMD5 instance, call "SmfHashMD5::Update()" as needed
 * on buffers full of bytes, and then call "SmfHashMD5::Finalize()", 
 * and finally use "SmfHashMD5::GetDigest() to fetch the digest.
 * To reuse the instance for another digest, first call 
 * "SmfHashMD5::Init()"
 */

// Based on public domain code by John Walker 

SmfHashMD5::SmfHashMD5()
{
    Init();
}

SmfHashMD5::~SmfHashMD5()
{
}

void SmfHashMD5::ByteReverse(UINT32* buffer, unsigned int count)
{
#if BYTE_ORDER == BIG_ENDIAN
    for (unsigned int i = 0; i < count; i++)
    {
        unsigned char* b = (unsigned char*)buffer;
        UINT32 t = ((((UINT32)b[3] << 8) | (UINT32)b[2]) << 16) |    
                    (((UINT32)b[1] << 8) | (UINT32)b[0]); 
        *buffer++ = t;      
    }     
#endif //
}  // end SmfHashMD5::ByteReverse()

void SmfHashMD5::Init()
{
    digest_buffer[0] = 0x67452301;
    digest_buffer[1] = 0xefcdab89;
    digest_buffer[2] = 0x98badcfe;
    digest_buffer[3] = 0x10325476;
    bit_count[0] = bit_count[1] = 0;
}  // end SmfHashMD5::Init()


// Update to reflect the concatenation  
// of another buffer full of bytes.
void SmfHashMD5::Update(const char* buffer, unsigned int buflen)
{
    // Update bit_count 
    UINT32 t = bit_count[0];
    if ((bit_count[0] = t + ((UINT32) buflen << 3)) < t)
	    bit_count[1]++; 	// Carry from low to high 
    bit_count[1] += buflen >> 29;
    t = (t >> 3) & 0x3f;  // remainder
    // Handle any leading odd-sized chunks
    if (0 != t) 
    {
	    unsigned char *p = (unsigned char*)data_buffer + t;
        t = 64 - t;
	    if (buflen < t) 
        {
	        memcpy(p, buffer, buflen);
	        return;
	    }
	    memcpy(p, buffer, t);
	    ByteReverse(data_buffer, 16);
	    Transform();
	    buffer += t;
	    buflen -= t;
    }
    // Process rest of data data_buffer 64-byte chunks 
    while (buflen >= 64) 
    {
	    memcpy(data_buffer, buffer, 64);
	    ByteReverse(data_buffer, 16);
	    Transform();
	    buffer += 64;
	    buflen -= 64;
    }
    // Cache any remaining bytes of data 
    memcpy(data_buffer, buffer, buflen);
}  // end SmfHashMD5::Update()


// Final wrapup - pad to 64-byte boundary with the bit pattern 
// 1 0* (64-bit count of bit_count processed, MSB-first)
void SmfHashMD5::Finalize()
{
    // Compute number of bytes mod 64 
    unsigned int count = (bit_count[0] >> 3) & 0x3F;

    // Set the first char of padding to 0x80.  This is safe 
    // since there is always at least one byte free 
    unsigned char* p = (unsigned char*)data_buffer + count;
    *p++ = 0x80;

    // Bytes of padding needed to make 64 bytes 
    count = 64 - 1 - count;

    // Pad out to 56 mod 64 
    if (count < 8) 
    {
	    // Two lots of padding:  Pad the first block to 64 bytes */
	    memset(p, 0, count);
	    ByteReverse(data_buffer, 16);
	    Transform();
        // Now fill the next block with 56 bytes of zeroes 
	    memset(data_buffer, 0, 56);
    } 
    else 
    {
	    // Pad block to 56 bytes 
	    memset(p, 0, count - 8);
    }
    ByteReverse(data_buffer, 14);

    // Append length data_buffer bit_count and transform 
    data_buffer[14] = bit_count[0];
    data_buffer[15] = bit_count[1];

    Transform();
    ByteReverse(digest_buffer, 4);
}  // end SmfHashMD5::Finalize()



/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step data_buffer the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void SmfHashMD5::Transform()
{
    UINT32 a, b, c, d;

    a = digest_buffer[0];
    b = digest_buffer[1];
    c = digest_buffer[2];
    d = digest_buffer[3];

    MD5STEP(F1, a, b, c, d, data_buffer[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, data_buffer[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, data_buffer[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, data_buffer[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, data_buffer[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, data_buffer[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, data_buffer[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, data_buffer[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, data_buffer[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, data_buffer[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, data_buffer[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, data_buffer[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, data_buffer[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, data_buffer[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, data_buffer[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, data_buffer[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, data_buffer[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, data_buffer[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, data_buffer[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, data_buffer[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, data_buffer[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, data_buffer[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, data_buffer[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, data_buffer[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, data_buffer[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, data_buffer[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, data_buffer[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, data_buffer[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, data_buffer[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, data_buffer[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, data_buffer[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, data_buffer[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, data_buffer[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, data_buffer[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, data_buffer[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, data_buffer[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, data_buffer[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, data_buffer[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, data_buffer[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, data_buffer[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, data_buffer[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, data_buffer[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, data_buffer[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, data_buffer[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, data_buffer[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, data_buffer[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, data_buffer[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, data_buffer[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, data_buffer[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, data_buffer[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, data_buffer[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, data_buffer[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, data_buffer[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, data_buffer[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, data_buffer[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, data_buffer[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, data_buffer[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, data_buffer[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, data_buffer[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, data_buffer[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, data_buffer[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, data_buffer[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, data_buffer[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, data_buffer[9] + 0xeb86d391, 21);

    digest_buffer[0] += a;
    digest_buffer[1] += b;
    digest_buffer[2] += c;
    digest_buffer[3] += d;
}  // end SmfHashMD5::Transform()
