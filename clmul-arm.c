/* clmul-arm.c - ARMv8 Carryless Multiply using C intrinsics  */
/*   Written and placed in public domain by Jeffrey Walton    */
/*   Based on code from ARM, and by Johannes Schneiders, Skip */
/*   Hovsmith and Barry O'Rourke for the mbedTLS project.     */

/* Visual Studio 2017 and above supports ARMv8, but its not clear how to detect */
/* it or use it at the moment. Also see http://stackoverflow.com/q/37244202,    */
/* http://stackoverflow.com/q/41646026, and http://stackoverflow.com/q/41688101 */
#if defined(__arm64__) || defined(__aarch64__)
# if defined(__GNUC__)
#  include <stdint.h>
# endif
# if defined(__ARM_NEON)
#  include <arm_neon.h>
# endif
/* GCC and LLVM Clang, but not Apple Clang */
# if defined(__GNUC__) && !defined(__apple_build_version__)
#  if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
#   include <arm_acle.h>
#  endif
# endif
#endif  /* ARM Headers */

/********************************/
/* GCC and compatible compilers */
/********************************/
#if defined(__GNUC__)
#if defined(__GNUC_STDC_INLINE__) || defined(__INLINE__)
# define MAYBE_INLINE inline
#else
# define MAYBE_INLINE
#endif

/* Schneiders, Hovsmith and O'Rourke discovered this trick.     */
/* It results in much better code generation in production code */
/* by avoiding D-register spills when using vgetq_lane_u64. The */
/* problem does not surface under minimal test cases.           */
MAYBE_INLINE uint8x16_t PMULL_LOW(const uint8x16_t a, const uint8x16_t b)
{
    uint8x16_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
        :"=w" (r) : "w" (a), "w" (b) );
    return r;
}

MAYBE_INLINE uint8x16_t PMULL_HIGH(const uint8x16_t a, const uint8x16_t b)
{
    uint8x16_t r;
    __asm __volatile("pmull2   %0.1q, %1.2d, %2.2d \n\t"
        :"=w" (r) : "w" (a), "w" (b) );
    return r;
}
#endif /* GCC and compatibles */

/**************************************/
/* Microsoft and compatible compilers */
/**************************************/
#if defined(_MSC_VER)
inline uint8x16_t PMULL_LOW(const uint8x16_t a, const uint8x16_t b)
{
    return (uint8x16_t)(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(a),0),
                                  vgetq_lane_u64(vreinterpretq_u64_u8(b),0)));
}

inline uint8x16_t PMULL_HIGH(const uint8x16_t a, const uint8x16_t b)
{
    return (uint8x16_t)(vmull_p64(vgetq_lane_u64(vreinterpretq_u64_u8(a),1),
                                  vgetq_lane_u64(vreinterpretq_u64_u8(b),1)));
}
#endif /* Microsoft and compatibles */

/*********************************************************/
/* Perform the multiplication and reduction in GF(2^128) */
/*********************************************************/
void clmul_arm(uint8_t r[16], const uint8_t a[16], const uint8_t b[16])
{
    uint8x16_t a8, b8, c8;
    uint8x16_t z, p;
    uint8x16_t r0, r1;
    uint8x16_t t0, t1;

    a8 = vrbitq_u8(vld1q_u8(a));
    b8 = vrbitq_u8(vld1q_u8(b));

    /* polynomial multiply */
    z = vdupq_n_u8(0);
    r0 = PMULL_LOW(a8, b8);
    r1 = PMULL_HIGH(a8, b8);
    t0 = vextq_u8(b8, b8, 8);
    t1 = PMULL_LOW(a8, t0);
    t0 = PMULL_HIGH(a8, t0);
    t0 = veorq_u8(t0, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);

    /* polynomial reduction */
    p = vreinterpretq_u8_u64(vdupq_n_u64(0x0000000000000087));
    t0 = PMULL_HIGH(r1, p);
    t1 = vextq_u8(t0, z, 8);
    r1 = veorq_u8(r1, t1);
    t1 = vextq_u8(z, t0, 8);
    r0 = veorq_u8(r0, t1);
    t0 = PMULL_LOW(r1, p);
    c8 = veorq_u8(r0, t0);

    vst1q_u8(r, vrbitq_u8(c8));
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

    clmul_arm(r, a, b);

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
