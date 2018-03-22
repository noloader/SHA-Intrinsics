/* sha256-p8.cxx - Power8 SHA extensions using C intrinsics  */
/*   Written and placed in public domain by Jeffrey Walton   */

/* sha256-p8.cxx rotates working variables in the SHA round function    */
/* and not the caller. Loop unrolling penalizes performance.            */
/* Loads and stores: https://gcc.gnu.org/ml/gcc/2015-03/msg00140.html.  */

/* We discovered a lot of ways to produce a dull implementation using   */
/* Power8 built-ins. The best strategy seems to be (1) use a vector     */
/* array for X[16]; (2) modify X[] in-place per round; and (3) use a    */
/* vector array S[8] for working vars. Rotating the working vars in the */
/* caller versus in the callee did not make a difference during         */
/* testing. We hope IBM will eventually publish a paper that provides   */
/* the methods and explains techniques for a performing implementation. */

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

// ALIGN16 when the library controls alignment
#define ALIGN16 __attribute__((aligned(16)))
typedef __vector unsigned char uint8x16_p8;
typedef __vector unsigned int  uint32x4_p8;

// Indexes into the S[] array
enum {A=0, B=1, C, D, E, F, G, H};

static const ALIGN16 uint32_t KEY256[] =
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

// More succinct, but not optimized as well
#if 0
uint32x4_p8 VEC_XL_BE(int offset, const uint8_t* data)
{
#if defined(__xlc__) || defined(__xlC__)
    return vec_xl_be(offset, data);
#else
    uint32x4_p8 res;
    __asm(" lxvd2x  %x0, %1, %2    \n\t"
          : "=wa" (res)
          : "b" (data), "r" (offset));
    return res;
#endif
}

// Unaligned load of a user message. The load is big-endian,
//   and then the message is permuted for 32-bit words.
template <class T> static inline
uint32x4_p8 VectorLoadMsg32x4(const T* data, int offset)
{
#if __LITTLE_ENDIAN__
    const uint8x16_p8 mask = {11,10,9,8, 15,14,13,12, 3,2,1,0, 7,6,5,4};
    const uint32x4_p8 r = VEC_XL_BE(offset, (uint8_t*)data);
    return (uint32x4_p8)vec_perm(r, r, mask);
#else
    return VEC_XL_BE(offset, (uint8_t*)data);
#endif
}
#endif

// Aligned load
template <class T> static inline
uint32x4_p8 VectorLoad32x4(const T* data, int offset)
{
    return (uint32x4_p8)vec_ld(offset, (uint8_t*)data);
}

// Unaligned load
template <class T> static inline
uint32x4_p8 VectorLoad32x4u(const T* data, int offset)
{
#if defined(TEST_SHA_XLC)
    return (uint32x4_p8)vec_xl(offset, (uint8_t*)data);
#else
    return (uint32x4_p8)vec_vsx_ld(offset, (uint8_t*)data);
#endif
}

// Aligned store
template <class T> static inline
void VectorStore32x4(const uint32x4_p8 val, T* data, int offset)
{
    vec_st((uint8x16_p8)val, offset, (uint8_t*)data);
}

// Unaligned store
template <class T> static inline
void VectorStore32x4u(const uint32x4_p8 val, T* data, int offset)
{
#if defined(TEST_SHA_XLC)
    vec_xst((uint8x16_p8)val, offset, (uint8_t*)data);
#else
    vec_vsx_st((uint8x16_p8)val, offset, (uint8_t*)data);
#endif
}

// Unaligned load of a user message. The load is big-endian,
//   and then the message is permuted for 32-bit words.
template <class T> static inline
uint32x4_p8 VectorLoadMsg32x4(const T* data, int offset)
{
#if __LITTLE_ENDIAN__
    const uint8x16_p8 mask = {3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12};
    const uint32x4_p8 r = VectorLoad32x4u(data, offset);
    return (uint32x4_p8)vec_perm(r, r, mask);
#else
    return VectorLoad32x4u(data, offset);
#endif
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
    return vec_sel(y, z, vec_xor(x, y));
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
    const uint8x16_p8 m2 = {0,1,2,3, 4,5,6,7, 16,17,18,19, 20,21,22,23};
    return vec_perm(vec_perm(a,b,m1), vec_perm(c,d,m1), m2);
}

template <unsigned int L> static inline
uint32x4_p8 VectorShiftLeft(const uint32x4_p8 val)
{
#if __LITTLE_ENDIAN__
    return (uint32x4_p8)vec_sld((uint8x16_p8)val, (uint8x16_p8)val, (16-L)&0xf);
#else
    return (uint32x4_p8)vec_sld((uint8x16_p8)val, (uint8x16_p8)val, L&0xf);
#endif
}

template <>
uint32x4_p8 VectorShiftLeft<0>(const uint32x4_p8 val) { return val; }

template <unsigned int R> static inline
void SHA256_ROUND1(uint32x4_p8 X[16], uint32x4_p8 S[8], const uint32x4_p8 K, const uint32x4_p8 M)
{
    uint32x4_p8 T1, T2;

    X[R] = M;
    T1 = S[H] + VectorSigma1(S[E]) + VectorCh(S[E],S[F],S[G]) + K + M;
    T2 = VectorSigma0(S[A]) + VectorMaj(S[A],S[B],S[C]);

    S[H] = S[G]; S[G] = S[F]; S[F] = S[E];
    S[E] = S[D] + T1;
    S[D] = S[C]; S[C] = S[B]; S[B] = S[A];
    S[A] = T1 + T2;
}

template <unsigned int R> static inline
void SHA256_ROUND2(uint32x4_p8 X[16], uint32x4_p8 S[8], const uint32x4_p8 K)
{
    // Indexes into the X[] array
    enum {IDX0=(R+0)&0xf, IDX1=(R+1)&0xf, IDX9=(R+9)&0xf, IDX14=(R+14)&0xf};

    const uint32x4_p8 s0 = Vector_sigma0(X[IDX1]);
    const uint32x4_p8 s1 = Vector_sigma1(X[IDX14]);

    uint32x4_p8 T1 = (X[IDX0] += s0 + s1 + X[IDX9]);
    T1 += S[H] + VectorSigma1(S[E]) + VectorCh(S[E],S[F],S[G]) + K;
    uint32x4_p8 T2 = VectorSigma0(S[A]) + VectorMaj(S[A],S[B],S[C]);

    S[H] = S[G]; S[G] = S[F]; S[F] = S[E];
    S[E] = S[D] + T1;
    S[D] = S[C]; S[C] = S[B]; S[B] = S[A];
    S[A] = T1 + T2;
}

/* Process multiple blocks. The caller is responsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
void sha256_process_p8(uint32_t state[8], const uint8_t data[], uint32_t length)
{
    uint32_t blocks = length / 64;
    if (blocks == 0) return;

    const uint32_t* k = reinterpret_cast<const uint32_t*>(KEY256);
    const uint32_t* m = reinterpret_cast<const uint32_t*>(data);

    uint32x4_p8 abcd = VectorLoad32x4u(state+0, 0);
    uint32x4_p8 efgh = VectorLoad32x4u(state+4, 0);

    while (blocks--)
    {
        uint32x4_p8 X[16], S[8], vm, vk;
        unsigned int i, offset=0;

        S[A] = abcd; S[E] = efgh;
        S[B] = VectorShiftLeft<4>(S[A]);
        S[F] = VectorShiftLeft<4>(S[E]);
        S[C] = VectorShiftLeft<4>(S[B]);
        S[G] = VectorShiftLeft<4>(S[F]);
        S[D] = VectorShiftLeft<4>(S[C]);
        S[H] = VectorShiftLeft<4>(S[G]);

        // Unroll the loop to provide the round number as a constexpr
        // for (unsigned int i=0; i<16; ++i)
        {
            vk = VectorLoad32x4(k, offset);
            vm = VectorLoadMsg32x4(m, offset);
            SHA256_ROUND1<0>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<1>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<2>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<3>(X,S, vk,vm);

            vk = VectorLoad32x4(k, offset);
            vm = VectorLoadMsg32x4(m, offset);
            SHA256_ROUND1<4>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<5>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<6>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<7>(X,S, vk,vm);

            vk = VectorLoad32x4(k, offset);
            vm = VectorLoadMsg32x4(m, offset);
            SHA256_ROUND1<8>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<9>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<10>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<11>(X,S, vk,vm);

            vk = VectorLoad32x4(k, offset);
            vm = VectorLoadMsg32x4(m, offset);
            SHA256_ROUND1<12>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<13>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<14>(X,S, vk,vm);

            vk = VectorShiftLeft<4>(vk);
            vm = VectorShiftLeft<4>(vm);
            SHA256_ROUND1<15>(X,S, vk,vm);
        }

        // Number of 32-bit words, not bytes
        m += 16;

        for (i=16; i<64; i+=16)
        {
            vk = VectorLoad32x4(k, offset);
            SHA256_ROUND2<0>(X,S, vk);
            SHA256_ROUND2<1>(X,S, VectorShiftLeft<4>(vk));
            SHA256_ROUND2<2>(X,S, VectorShiftLeft<8>(vk));
            SHA256_ROUND2<3>(X,S, VectorShiftLeft<12>(vk));
            offset+=16;

            vk = VectorLoad32x4(k, offset);
            SHA256_ROUND2<4>(X,S, vk);
            SHA256_ROUND2<5>(X,S, VectorShiftLeft<4>(vk));
            SHA256_ROUND2<6>(X,S, VectorShiftLeft<8>(vk));
            SHA256_ROUND2<7>(X,S, VectorShiftLeft<12>(vk));
            offset+=16;

            vk = VectorLoad32x4(k, offset);
            SHA256_ROUND2<8>(X,S, vk);
            SHA256_ROUND2<9>(X,S, VectorShiftLeft<4>(vk));
            SHA256_ROUND2<10>(X,S, VectorShiftLeft<8>(vk));
            SHA256_ROUND2<11>(X,S, VectorShiftLeft<12>(vk));
            offset+=16;

            vk = VectorLoad32x4(k, offset);
            SHA256_ROUND2<12>(X,S, vk);
            SHA256_ROUND2<13>(X,S, VectorShiftLeft<4>(vk));
            SHA256_ROUND2<14>(X,S, VectorShiftLeft<8>(vk));
            SHA256_ROUND2<15>(X,S, VectorShiftLeft<12>(vk));
            offset+=16;
        }

        abcd += VectorPack(S[A],S[B],S[C],S[D]);
        efgh += VectorPack(S[E],S[F],S[G],S[H]);
    }

    VectorStore32x4u(abcd, state+0, 0);
    VectorStore32x4u(efgh, state+4, 0);
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

    /* initial state */
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
