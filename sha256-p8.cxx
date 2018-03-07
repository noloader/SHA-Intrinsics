/* sha256-p8.cxx - Power8 SHA extensions using C intrinsics  */
/*   Written and placed in public domain by Jeffrey Walton   */

/* sha256-p8.cxx rotates working variables in the SHA round function   */
/* and not the caller. Loop unrolling penalizes performance.           */
/* Loads and stores: https://gcc.gnu.org/ml/gcc/2015-03/msg00140.html. */

/* xlC -DTEST_MAIN -qarch=pwr8 -qaltivec sha256-p8.cxx -o sha256-p8.exe  */
/* g++ -DTEST_MAIN -mcpu=power8 sha256-p8.cxx -o sha256-p8.exe           */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if defined(__ALTIVEC__)
# include <altivec.h>
# undef vector
# undef pixel
# undef bool
#endif

#if defined(__xlc__) || defined(__xlC__)
# define TEST_SHA_XLC 1
#elif defined(__clang__)
# define TEST_SHA_CLANG 1
#elif defined(__GNUC__)
# define TEST_SHA_GCC 1
#endif

#define ALIGN16 __attribute__((aligned(16)))
typedef __vector unsigned char uint8x16_p8;
typedef __vector unsigned int  uint32x4_p8;

static const ALIGN16 uint32_t K[] =
{
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

// Aligned load
template <class T> static inline
uint32x4_p8 VectorLoad32x4(const T* data, int offset)
{
    return vec_ld(offset, (uint32_t*)data);
}

// Unaligned load
template <class T> static inline
uint32x4_p8 VectorLoad32x4u(const T* data, int offset)
{
#if defined(TEST_SHA_XLC)
    return vec_xl(offset, (uint32_t*)data);
#else
    return vec_vsx_ld(offset, (uint32_t*)data);
#endif
}

// Aligned store
template <class T> static inline
void VectorStore32x4(const uint32x4_p8 val, T* data, int offset)
{
    vec_st(val, offset, (uint32_t*)data);
}

// Unaligned store
template <class T> static inline
void VectorStore32x4u(const uint32x4_p8 val, T* data, int offset)
{
#if defined(TEST_SHA_XLC)
    vec_xst(val, offset, (uint32_t*)data);
#else
    vec_vsx_st(val, offset, (uint32_t*)data);
#endif
}

static inline
uint32x4_p8 VectorPermute32x4(const uint32x4_p8 val, const uint8x16_p8 mask)
{
    return (uint32x4_p8)vec_perm(val, val, mask);
}

static inline
uint32x4_p8 VectorCh(const uint32x4_p8 x, const uint32x4_p8 y, const uint32x4_p8 z)
{
    // The trick below is due to Andy Polyakov and Jack Lloyd
    return vec_sel(z,y,x);
}

static inline
uint32x4_p8 VectorMaj(const uint32x4_p8 x, const uint32x4_p8 y, const uint32x4_p8 z)
{
    // The trick below is due to Andy Polyakov and Jack Lloyd
    const uint32x4_p8 xy = vec_xor(x, y);
    return vec_sel(y, z, xy);
}

static inline
uint32x4_p8 Vector_sigma0(const uint32x4_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmaw(val, 0, 0);
#else
    return __builtin_crypto_vshasigmaw(val, 0, 0);
#endif
}

static inline
uint32x4_p8 Vector_sigma1(const uint32x4_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmaw(val, 0, 0xf);
#else
    return __builtin_crypto_vshasigmaw(val, 0, 0xf);
#endif
}

static inline
uint32x4_p8 VectorSigma0(const uint32x4_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmaw(val, 1, 0);
#else
    return __builtin_crypto_vshasigmaw(val, 1, 0);
#endif
}

static inline
uint32x4_p8 VectorSigma1(const uint32x4_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmaw(val, 1, 0xf);
#else
    return __builtin_crypto_vshasigmaw(val, 1, 0xf);
#endif
}

static inline
uint32x4_p8 VectorPack(const uint32x4_p8 a, const uint32x4_p8 b,
                       const uint32x4_p8 c, const uint32x4_p8 d)
{
    const uint8x16_p8 m1 = {0,1,2,3, 16,17,18,19, 0,0,0,0, 0,0,0,0};
    const uint8x16_p8 m2 = {0,1,2,3, 4,5,6,7, 16,17,18,19, 0,0,0,0};
    const uint8x16_p8 m3 = {0,1,2,3, 4,5,6,7, 8,9,10,11, 16,17,18,19};

    return vec_perm(vec_perm(vec_perm(a,b,m1),c,m2),d,m3);
}

template <unsigned int L> static inline
uint32x4_p8 VectorShiftLeft(const uint32x4_p8 val)
{
#if (__LITTLE_ENDIAN__)
    return vec_sld(val, val, (16-L)&0xf);
#else
    return vec_sld(val, val, L&0xf);
#endif
}

template <>
uint32x4_p8 VectorShiftLeft<0>(const uint32x4_p8 val) { return val; }

template <>
uint32x4_p8 VectorShiftLeft<16>(const uint32x4_p8 val) { return val; }

// +2 because Schedule reads beyond the last element
void SHA256_SCHEDULE(uint32_t W[64+2], const uint8_t* D)
{
    uint32_t* w = reinterpret_cast<uint32_t*>(W);
    const uint32_t* d = reinterpret_cast<const uint32_t*>(D);
    unsigned int i=0;

#if (__LITTLE_ENDIAN__)
    const uint8x16_p8 mask = {3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12};
    for (i=0; i<16; i+=4, d+=4, w+=4)
        VectorStore32x4u(VectorPermute32x4(VectorLoad32x4u(d, 0), mask), w, 0);
#else
    for ( ; i<16; i+=4, d+=4, w+=4)
        VectorStore32x4u(VectorLoad32x4u(d, 0), w, 0);
#endif

    // At i=62, W[i-2] reads the 65th and 66th elements. W[] has 2 extra "don't care" elements.
    // The stride of 2 when walking the W[] array means we have to access through unaligned loads.
    for ( ; i < 64; i+=2, w+=2)
    {
        const uint32x4_p8 s0 = Vector_sigma0(VectorLoad32x4u(w, -60));  // W[i-15]
        const uint32x4_p8 w0 = VectorLoad32x4u(w, -64);                 // W[i-16]
        const uint32x4_p8 s1 = Vector_sigma1(VectorLoad32x4u(w, -8));   // W[i-2]
        const uint32x4_p8 w1 = VectorLoad32x4u(w, -28);                 // W[i-7]

        const uint32x4_p8 r = vec_add(s1, vec_add(w1, vec_add(s0, w0)));
        VectorStore32x4u(r, w, 0);  // W[i]
    }
}

template <unsigned int R> static inline
void SHA256_ROUND(const uint32x4_p8 K, const uint32x4_p8 W,
        uint32x4_p8& a, uint32x4_p8& b, uint32x4_p8& c, uint32x4_p8& d,
        uint32x4_p8& e, uint32x4_p8& f, uint32x4_p8& g, uint32x4_p8& h )
{
    const uint32x4_p8 k = VectorShiftLeft<R*4>(K);
    const uint32x4_p8 w = VectorShiftLeft<R*4>(W);

    // T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]
    const uint32x4_p8 T1 = vec_add(h, vec_add(vec_add(vec_add(VectorSigma1(e), VectorCh(e,f,g)), k), w));

    // T2 = Sigma0(a) + Maj(a,b,c)
    const uint32x4_p8 T2 = vec_add(VectorSigma0(a), VectorMaj(a,b,c));

    h = g; g = f; f = e;
    e = vec_add(d, T1);
    d = c; c = b; b = a;
    a = vec_add(T1, T2);
}

/* Process multiple blocks. The caller is resonsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
void sha256_process_p8(uint32_t state[8], const uint8_t data[], uint32_t length)
{
    uint32_t blocks = length / 64;
    if (blocks == 0) return;

    // +2 because Schedule reads beyond the last element
    ALIGN16 uint32_t W[64+2];

    uint32x4_p8 abcd = VectorLoad32x4u(state,  0);
    uint32x4_p8 efgh = VectorLoad32x4u(state, 16);
    uint32x4_p8 a,b,c,d,e,f,g,h;

    while (blocks--)
    {
        SHA256_SCHEDULE(W, data);

        a = abcd; e = efgh;
        b = VectorShiftLeft<4>(a);
        f = VectorShiftLeft<4>(e);
        c = VectorShiftLeft<4>(b);
        g = VectorShiftLeft<4>(f);
        d = VectorShiftLeft<4>(c);
        h = VectorShiftLeft<4>(g);

        for (unsigned int i=0; i<64; i+=4)
        {
            const uint32x4_p8 k = VectorLoad32x4u(K, i*4);
            const uint32x4_p8 w = VectorLoad32x4u(W, i*4);
            SHA256_ROUND<0>(w,k, a,b,c,d,e,f,g,h);
            SHA256_ROUND<1>(w,k, a,b,c,d,e,f,g,h);
            SHA256_ROUND<2>(w,k, a,b,c,d,e,f,g,h);
            SHA256_ROUND<3>(w,k, a,b,c,d,e,f,g,h);
        }

        abcd = vec_add(abcd, VectorPack(a,b,c,d));
        efgh = vec_add(efgh, VectorPack(e,f,g,h));
        data += 64;
    }

    VectorStore32x4u(abcd, state,  0);
    VectorStore32x4u(efgh, state, 16);
}

#if defined(TEST_MAIN)

#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[])
{
    /* empty message with padding */
    uint8_t message[64];
    memset(message, 0x00, sizeof(message));
    message[0] = 0x80;

    /* intial state */
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    sha256_process_p8(state, message, sizeof(message));

    const uint8_t b1 = (uint8_t)(state[0] >> 24);
    const uint8_t b2 = (uint8_t)(state[0] >> 16);
    const uint8_t b3 = (uint8_t)(state[0] >>  8);
    const uint8_t b4 = (uint8_t)(state[0] >>  0);
    const uint8_t b5 = (uint8_t)(state[1] >> 24);
    const uint8_t b6 = (uint8_t)(state[1] >> 16);
    const uint8_t b7 = (uint8_t)(state[1] >>  8);
    const uint8_t b8 = (uint8_t)(state[1] >>  0);

    /* e3b0c44298fc1c14... */
    printf("SHA256 hash of empty message: ");
    printf("%02X%02X%02X%02X%02X%02X%02X%02X...\n",
        b1, b2, b3, b4, b5, b6, b7, b8);

    int success = ((b1 == 0xE3) && (b2 == 0xB0) && (b3 == 0xC4) && (b4 == 0x42) &&
                    (b5 == 0x98) && (b6 == 0xFC) && (b7 == 0x1C) && (b8 == 0x14));

    if (success)
        printf("Success!\n");
    else
        printf("Failure!\n");

    return (success != 0 ? 0 : 1);
}

#endif
