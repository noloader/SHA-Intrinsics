/**
 * cpuid.c
 *
 * Checks if CPU has support of SHA instructions
 *
 * @author kryukov@frtk.ru
 * @version 4.0
 */

#ifndef SILENT
#include <stdio.h>
#endif

#if defined(__clang__) || defined(__GNUC__) || defined(__INTEL_COMPILER)

#include <cpuid.h>
static int supports_sha_ni(void)
{
    unsigned int CPUInfo[4];
    __cpuid(0, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
    if (CPUInfo[0] < 7)
        return 0;

    __cpuid_count(7, 0, CPUInfo[0], CPUInfo[1], CPUInfo[2], CPUInfo[3]);
    return CPUInfo[1] & (1 << 29); /* SHA */
}

#else /* defined(__clang__) || defined(__GNUC__) */

static int supports_sha_ni(void)
{
    unsigned int CPUInfo[4];
    __cpuid(CPUInfo, 0);  
    if (CPUInfo[0] < 7)
        return 0;

    __cpuidex(CPUInfo, 7, 0);
    return CPUInfo[1] & (1 << 29); /* Check SHA */
}

#endif /* defined(__clang__) || defined(__GNUC__) */

int main(int argc, char ** argv)
{
    const int res = !supports_sha_ni();
#ifndef SILENT
    printf("This CPU %s SHA-NI\n", res ? "does not support" : "supports");
#endif
    return res;

}
