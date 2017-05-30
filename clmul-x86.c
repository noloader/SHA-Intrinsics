/* clmul-x86.c - Intel Carryless Multiply using C intrinsics  */
/*   Written and place in public domain by Jeffrey Walton     */
/*   Based on code from Intel CLMUL guide                     */

/* Include the GCC super header */
#if defined(__GNUC__)
# include <stdint.h>
# include <x86intrin.h>
#endif

/* Microsoft supports clmul extensions as of Visual Studio VS2008 */
#if defined(_MSC_VER)
# include <immintrin.h>
# define WIN32_LEAN_AND_MEAN
# include <Windows.h>
typedef UINT8 uint8_t;
#endif

/* Perform the multiplication and reduction in GF(2^128) */
void clmul_x86(uint8_t r[16], const uint8_t a[16], const uint8_t b[16])
{
    const __m128i MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

    __m128i a1 = _mm_loadu_si128((const __m128i*)a);
    __m128i b1 = _mm_loadu_si128((const __m128i*)b);

    a1 = _mm_shuffle_epi8(a1, MASK);
    b1 = _mm_shuffle_epi8(b1, MASK);

    __m128i T0, T1, T2, T3, T4, T5;

    T0 = _mm_clmulepi64_si128(a1, b1, 0x00);
    T1 = _mm_clmulepi64_si128(a1, b1, 0x01);
    T2 = _mm_clmulepi64_si128(a1, b1, 0x10);
    T3 = _mm_clmulepi64_si128(a1, b1, 0x11);

    T1 = _mm_xor_si128(T1, T2);
    T2 = _mm_slli_si128(T1, 8);
    T1 = _mm_srli_si128(T1, 8);
    T0 = _mm_xor_si128(T0, T2);
    T3 = _mm_xor_si128(T3, T1);

    T4 = _mm_srli_epi32(T0, 31);
    T0 = _mm_slli_epi32(T0, 1);

    T5 = _mm_srli_epi32(T3, 31);
    T3 = _mm_slli_epi32(T3, 1);

    T2 = _mm_srli_si128(T4, 12);
    T5 = _mm_slli_si128(T5, 4);
    T4 = _mm_slli_si128(T4, 4);
    T0 = _mm_or_si128(T0, T4);
    T3 = _mm_or_si128(T3, T5);
    T3 = _mm_or_si128(T3, T2);

    T4 = _mm_slli_epi32(T0, 31);
    T5 = _mm_slli_epi32(T0, 30);
    T2 = _mm_slli_epi32(T0, 25);

    T4 = _mm_xor_si128(T4, T5);
    T4 = _mm_xor_si128(T4, T2);
    T5 = _mm_srli_si128(T4, 4);
    T3 = _mm_xor_si128(T3, T5);
    T4 = _mm_slli_si128(T4, 12);
    T0 = _mm_xor_si128(T0, T4);
    T3 = _mm_xor_si128(T3, T0);

    T4 = _mm_srli_epi32(T0, 1);
    T1 = _mm_srli_epi32(T0, 2);
    T2 = _mm_srli_epi32(T0, 7);
    T3 = _mm_xor_si128(T3, T1);
    T3 = _mm_xor_si128(T3, T2);
    T3 = _mm_xor_si128(T3, T4);

    T3 = _mm_shuffle_epi8(T3, MASK);

    _mm_storeu_si128((__m128i*)r, T3);
}

#if defined(TEST_MAIN)

#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[])
{
    /* A's high nibble is 0x01, B's high nibble is 0x02 */
    uint8_t a[16] = {0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x18,0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,0x10};
    uint8_t b[16] = {0x2f,0x2e,0x2d,0x2c,0x2b,0x2a,0x28,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20};
    uint8_t r[16];

    clmul_x86(r, a, b);

    /* 4a3363BDA2626B6... */
    printf("GHASH of message: ");
    printf("%02X%02X%02X%02X%02X%02X%02X%02X...",
        r[0] & 0xFF, r[1] & 0xFF, r[2] & 0xFF, r[3] & 0xFF,
        r[4] & 0xFF, r[5] & 0xFF, r[6] & 0xFF, r[7] & 0xFF);

    int success = (r[0] == 0x4A && r[1] == 0x83 && r[2] == 0x36 && r[3] == 0x3B &&
        r[4] == 0xDA && r[5] == 0x26 && r[6] == 0x26 && r[7] == 0xB6);

    if (success)
        printf("Success!\n");
    else
        printf("Failure!\n");

    return (success != 0 ? 0 : 1);
}

#endif
