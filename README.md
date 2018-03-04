# SHA-Intrinsics

This GitHub repository contains source code for SHA-1, SHA-224, SHA-256 and SHA-512 compress function using Intel SHA and ARMv8 SHA intrinsics, and Power8 built-ins. The source files should be portable across toolchains which support the Intel and ARMv8 SHA extensions.

Only the SHA-1, SHA-224, SHA-256 and SHA-512 compression functions are provided. The functions operate on full blocks. Users must set initial state, and users must pad the last block. The small sample program included with each source file does both on an empty message.

## Intel SHA

To compile the x86 sources on an Intel machine, be sure your CFLAGS include `-msse4 -msha`. To compile the ARM sources on an ARMv8 machine, be sure your CFLAGS include `-march=armv8-a+crc+crypto`. Apple iOS CFLAGS should include `-arch arm64` and a system root like `-isysroot  /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS8.2.sdk`.

The x86 source files are based on code from Intel, and code by Sean Gulley for the miTLS project. You can find the miTLS GitHub at http://github.com/mitls.

## ARM SHA

The ARM source files are based on code from ARM, and code by Johannes Schneiders, Skip Hovsmith and Barry O'Rourke for the mbedTLS project. You can find the mbedTLS GitHub at http://github.com/ARMmbed/mbedtls. Prior to ARM's implementation, Critical Blue provided the source code and pull request at http://github.com/CriticalBlue/mbedtls.

If you want to test the programs but don't have a capable machine on hand, then you can use the Intel Software Development Emulator. You can find it at http://software.intel.com/en-us/articles/intel-software-development-emulator.

## Power8 SHA

The Power8 source file is a work in progress. The main problem at the moment is speed. The SHA-256 implementation using Power8 built-ins is 1.5 to 2 times slower than C++ so it is not suitable for production. There are several problem areas including the optimizations of `Ch(e,f,g)` and `Maj(a,b,c)`.

### GCC112, ppc64-le, 3.2 GHz

|  Impl  |   MiB/s   |  Cyc/byte  |
| ------ | --------- | ---------- |
|   C++  |    138    |    19.51   |
| Power8 |     91    |    35.7    |

### GCC119, ppc64-be, 4.1 GHz

|  Impl  |   MiB/s   |  Cyc/byte  |
| ------ | --------- | ---------- |
|   C++  |    385    |    10.16   |
| Power8 |    172    |    22.67   |

## Benchmarks

The speedups can be tricky to measure, but concrete numbers are availble from Jack Lloyd's Botan. The relative speedups using a three second benchmark under the command `./botan speed --msec=3000 SHA-1 SHA-224 SHA-256` are as follows. The measurements were taken from a Intel Celeron J3455, and an ARMv8 LeMaker HiKey.

* Intel x86, SHA-1, GCC 6.2 - approximately 4.3x
* Intel x86, SHA-1, Clang 3.8 - approximately 4.5x
* Intel x86, SHA-224, GCC 6.2 - approximately 5.8x
* Intel x86, SHA-224, Clang 3.8 - approximately 5.8x
* Intel x86, SHA-256, GCC 6.2 - approximately 5.8x
* Intel x86, SHA-256, Clang 3.8 - approximately 5.8x
* ARMv8, SHA-1, GCC 4.9 - approximately 4.8x
* ARMv8, SHA-1, Clang 3.5 - approximately 5.9x
* ARMv8, SHA-224, GCC 4.9 - approximately 9.2x
* ARMv8, SHA-224, Clang 3.5 - approximately 12.6x
* ARMv8, SHA-256, GCC 4.9 - approximately 9.2x
* ARMv8, SHA-256, Clang 3.5 - approximately 12.6x
