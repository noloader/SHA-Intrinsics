/* sha512-p8.cxx - Power8 SHA extensions using C intrinsics  */
/*   Written and placed in public domain by Jeffrey Walton   */

/* sha512-p8.cxx rotates working variables in the SHA round function    */
/* and not the caller. Loop unrolling penalizes performance.            */
/* Loads and stores: https://gcc.gnu.org/ml/gcc/2015-03/msg00140.html.  */

/* We discovered a lot of ways to produce a dull implementation using   */
/* Power8 built-ins. The best strategy seems to be (1) use a vector     */
/* array for X[16]; (2) modify X[] in-place per round; and (3) use a    */
/* vector array S[8] for working vars. Rotating the working vars in the */
/* caller versus in the callee did not make a difference during         */
/* testing. We hope IBM will eventually publish a paper that provides   */
/* the methods and explains techniques for a performing implementation. */

/* xlC -DTEST_MAIN -qarch=pwr8 -qaltivec sha512-p8.cxx -o sha512-p8.exe  */
/* g++ -DTEST_MAIN -mcpu=power8 sha512-p8.cxx -o sha512-p8.exe           */

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
typedef __vector unsigned long long uint64x2_p8;

// Indexes into the S[] array
enum {A=0, B=1, C, D, E, F, G, H};

static const ALIGN16 uint64_t KEY512[] =
{
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// Aligned load
template <class T> static inline
uint64x2_p8 VectorLoad64x2(const T* data, int offset)
{
    return (uint64x2_p8)vec_ld(offset, (uint8_t*)data);
}

// Unaligned load
template <class T> static inline
uint64x2_p8 VectorLoad64x2u(const T* data, int offset)
{
#if defined(TEST_SHA_XLC)
    return (uint64x2_p8)vec_xl(offset, (uint8_t*)data);
#else
    return (uint64x2_p8)vec_vsx_ld(offset, (uint8_t*)data);
#endif
}

// Aligned store
template <class T> static inline
void VectorStore64x2(const uint64x2_p8 val, T* data, int offset)
{
    vec_st((uint8x16_p8)val, offset, (uint8_t*)data);
}

// Unaligned store
template <class T> static inline
void VectorStore64x2u(const uint64x2_p8 val, T* data, int offset)
{
#if defined(TEST_SHA_XLC)
    vec_xst((uint8x16_p8)val, offset, (uint8_t*)data);
#else
    vec_vsx_st((uint8x16_p8)val, offset, (uint8_t*)data);
#endif
}

// Unaligned load of a user message. The load is big-endian,
//   and then the message is permuted for 64-bit words.
template <class T> static inline
uint64x2_p8 VectorLoadMsg64x2(const T* data, int offset)
{
#if __LITTLE_ENDIAN__
    // const uint8x16_p8 mask = {0,1,2,3, 4,5,6,7, 8,9,10,11, 12,13,14,15};
    const uint8x16_p8 mask = {7,6,5,4, 3,2,1,0, 15,14,13,12, 11,10,9,8};
    const uint64x2_p8 r = VectorLoad64x2u(data, offset);
    return (uint64x2_p8)vec_perm(r, r, mask);
#else
    return VectorLoad64x2u(data, offset);
#endif
}

static inline
uint64x2_p8 VectorCh(const uint64x2_p8 x, const uint64x2_p8 y, const uint64x2_p8 z)
{
    // The trick below is due to Andy Polyakov and Jack Lloyd
    return vec_sel(z,y,x);
}

static inline
uint64x2_p8 VectorMaj(const uint64x2_p8 x, const uint64x2_p8 y, const uint64x2_p8 z)
{
    // The trick below is due to Andy Polyakov and Jack Lloyd
    return vec_sel(y, z, vec_xor(x, y));
}

static inline
uint64x2_p8 Vector_sigma0(const uint64x2_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmad(val, 0, 0);
#else
    return __builtin_crypto_vshasigmad(val, 0, 0);
#endif
}

static inline
uint64x2_p8 Vector_sigma1(const uint64x2_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmad(val, 0, 0xf);
#else
    return __builtin_crypto_vshasigmad(val, 0, 0xf);
#endif
}

static inline
uint64x2_p8 VectorSigma0(const uint64x2_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmad(val, 1, 0);
#else
    return __builtin_crypto_vshasigmad(val, 1, 0);
#endif
}

static inline
uint64x2_p8 VectorSigma1(const uint64x2_p8 val)
{
#if defined(TEST_SHA_XLC)
    return __vshasigmad(val, 1, 0xf);
#else
    return __builtin_crypto_vshasigmad(val, 1, 0xf);
#endif
}

static inline
uint64x2_p8 VectorPack(const uint64x2_p8 x, const uint64x2_p8 y)
{
    const uint8x16_p8 m = {0,1,2,3, 4,5,6,7, 16,17,18,19, 20,21,22,23};
    return vec_perm(x,y,m);
}

template <unsigned int L> static inline
uint64x2_p8 VectorShiftLeft(const uint64x2_p8 val)
{
#if __LITTLE_ENDIAN__
    return (uint64x2_p8)vec_sld((uint8x16_p8)val, (uint8x16_p8)val, (16-L)&0xf);
#else
    return (uint64x2_p8)vec_sld((uint8x16_p8)val, (uint8x16_p8)val, L&0xf);
#endif
}

template <>
uint64x2_p8 VectorShiftLeft<0>(const uint64x2_p8 val) { return val; }

template <unsigned int R> static inline
void SHA512_ROUND1(uint64x2_p8 X[16], uint64x2_p8 S[8], const uint64x2_p8 K, const uint64x2_p8 M)
{
    uint64x2_p8 T1, T2;

    X[R] = M;
    T1 = S[H] + VectorSigma1(S[E]) + VectorCh(S[E],S[F],S[G]) + K + M;
    T2 = VectorSigma0(S[A]) + VectorMaj(S[A],S[B],S[C]);

    S[H] = S[G]; S[G] = S[F]; S[F] = S[E];
    S[E] = S[D] + T1;
    S[D] = S[C]; S[C] = S[B]; S[B] = S[A];
    S[A] = T1 + T2;
}

template <unsigned int R> static inline
void SHA512_ROUND2(uint64x2_p8 X[16], uint64x2_p8 S[8], const uint64x2_p8 K)
{
    // Indexes into the X[] array
    enum {IDX0=(R+0)&0xf, IDX1=(R+1)&0xf, IDX9=(R+9)&0xf, IDX14=(R+14)&0xf};

    const uint64x2_p8 s0 = Vector_sigma0(X[IDX1]);
    const uint64x2_p8 s1 = Vector_sigma1(X[IDX14]);

    uint64x2_p8 T1 = (X[IDX0] += s0 + s1 + X[IDX9]);
    T1 += S[H] + VectorSigma1(S[E]) + VectorCh(S[E],S[F],S[G]) + K;
    uint64x2_p8 T2 = VectorSigma0(S[A]) + VectorMaj(S[A],S[B],S[C]);

    S[H] = S[G]; S[G] = S[F]; S[F] = S[E];
    S[E] = S[D] + T1;
    S[D] = S[C]; S[C] = S[B]; S[B] = S[A];
    S[A] = T1 + T2;
}

/* Process multiple blocks. The caller is responsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
void sha512_process_p8(uint64_t state[8], const uint8_t data[], uint32_t length)
{
    uint32_t blocks = length / 128;
    if (blocks == 0) return;

    const uint64_t* k = reinterpret_cast<const uint64_t*>(KEY512);
    const uint64_t* m = reinterpret_cast<const uint64_t*>(data);

    uint64x2_p8 ab = VectorLoad64x2u(state+0, 0);
    uint64x2_p8 cd = VectorLoad64x2u(state+2, 0);
    uint64x2_p8 ef = VectorLoad64x2u(state+4, 0);
    uint64x2_p8 gh = VectorLoad64x2u(state+6, 0);

    while (blocks--)
    {
        uint64x2_p8 X[16], S[8], vm, vk;
        unsigned int i, offset=0;

        S[A] = ab; S[C] = cd;
        S[E] = ef; S[G] = gh;
        S[B] = VectorShiftLeft<8>(S[A]);
        S[D] = VectorShiftLeft<8>(S[C]);
        S[F] = VectorShiftLeft<8>(S[E]);
        S[H] = VectorShiftLeft<8>(S[G]);

        // Unroll the loop to provide the round number as a constexpr
        // for (unsigned int i=0; i<16; ++i)
        {
            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<0>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<1>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<2>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<3>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<4>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<5>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<6>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<7>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<8>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<9>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<10>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<11>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<12>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<13>(X,S, vk,vm);

            vk = VectorLoad64x2(k, offset);
            vm = VectorLoadMsg64x2(m, offset);
            SHA512_ROUND1<14>(X,S, vk,vm);
            offset+=16;

            vk = VectorShiftLeft<8>(vk);
            vm = VectorShiftLeft<8>(vm);
            SHA512_ROUND1<15>(X,S, vk,vm);
        }

        // Number of 64-bit words, not bytes
        m += 16;

        for (i=16; i<80; i+=16)
        {
            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<0>(X,S, vk);
            SHA512_ROUND2<1>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<2>(X,S, vk);
            SHA512_ROUND2<3>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<4>(X,S, vk);
            SHA512_ROUND2<5>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<6>(X,S, vk);
            SHA512_ROUND2<7>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<8>(X,S, vk);
            SHA512_ROUND2<9>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<10>(X,S, vk);
            SHA512_ROUND2<11>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<12>(X,S, vk);
            SHA512_ROUND2<13>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;

            vk = VectorLoad64x2(k, offset);
            SHA512_ROUND2<14>(X,S, vk);
            SHA512_ROUND2<15>(X,S, VectorShiftLeft<8>(vk));
            offset+=16;
        }

        ab += VectorPack(S[A],S[B]);
        cd += VectorPack(S[C],S[D]);
        ef += VectorPack(S[E],S[F]);
        gh += VectorPack(S[G],S[H]);
    }

    VectorStore64x2u(ab, state+0, 0);
    VectorStore64x2u(cd, state+2, 0);
    VectorStore64x2u(ef, state+4, 0);
    VectorStore64x2u(gh, state+6, 0);
}

#if defined(TEST_MAIN)

#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[])
{
    /* empty message with padding */
    uint8_t message[128];
    memset(message, 0x00, sizeof(message));
    message[0] = 0x80;

    /* initial state */
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };

    sha512_process_p8(state, message, sizeof(message));

    const uint8_t b1 = (uint8_t)(state[0] >> 56);
    const uint8_t b2 = (uint8_t)(state[0] >> 48);
    const uint8_t b3 = (uint8_t)(state[0] >> 40);
    const uint8_t b4 = (uint8_t)(state[0] >> 32);
    const uint8_t b5 = (uint8_t)(state[0] >> 24);
    const uint8_t b6 = (uint8_t)(state[0] >> 16);
    const uint8_t b7 = (uint8_t)(state[0] >>  8);
    const uint8_t b8 = (uint8_t)(state[0] >>  0);

    /* cf83e1357eefb8bd... */
    printf("SHA512 hash of empty message: ");
    printf("%02X%02X%02X%02X%02X%02X%02X%02X...\n",
        b1, b2, b3, b4, b5, b6, b7, b8);

    int success = ((b1 == 0xCF) && (b2 == 0x83) && (b3 == 0xE1) && (b4 == 0x35) &&
                    (b5 == 0x7E) && (b6 == 0xEF) && (b7 == 0xB8) && (b8 == 0xBD));

    if (success)
        printf("Success!\n");
    else
        printf("Failure!\n");

    return (success != 0 ? 0 : 1);
}

#endif
