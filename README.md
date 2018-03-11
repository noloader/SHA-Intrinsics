# SHA-Intrinsics

This GitHub repository contains source code for SHA-1, SHA-224, SHA-256 and SHA-512 compress function using Intel SHA and ARMv8 SHA intrinsics, and Power8 built-ins. The source files should be portable across toolchains which support the Intel and ARMv8 SHA extensions.

Only the SHA-1, SHA-224, SHA-256 and SHA-512 compression functions are provided. The functions operate on full blocks. Users must set initial state, and users must pad the last block. The small sample program included with each source file does both on an empty message.

## Intel SHA

To compile the x86 sources on an Intel machine, be sure your CFLAGS include `-msse4 -msha`.

The x86 source files are based on code from Intel, and code by Sean Gulley for the miTLS project. You can find the miTLS GitHub at http://github.com/mitls.

If you want to test the programs but don't have a capable machine on hand, then you can use the Intel Software Development Emulator. You can find it at http://software.intel.com/en-us/articles/intel-software-development-emulator.

## ARM SHA

To compile the ARM sources on an ARMv8 machine, be sure your CFLAGS include `-march=armv8-a+crc+crypto`. Apple iOS CFLAGS should include `-arch arm64` and a system root like `-isysroot  /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS8.2.sdk`.

The ARM source files are based on code from ARM, and code by Johannes Schneiders, Skip Hovsmith and Barry O'Rourke for the mbedTLS project. You can find the mbedTLS GitHub at http://github.com/ARMmbed/mbedtls. Prior to ARM's implementation, Critical Blue provided the source code and pull request at http://github.com/CriticalBlue/mbedtls.

If you want to test the programs but don't have a capable machine on hand, then you can use the ARM  Fixed Virtual Platforms. You can find it at https://developer.arm.com/products/system-design/fixed-virtual-platforms.

## Power8 SHA

The Power8 source files are just about complete. Perforance increases significantly using built-ins, but it seems like there is still room for improvement. One of the problems we are having is IBM's documentation sucks. Namely, there is none. We kind of knew that going into things because we experienced the same problems when implementaing AES on Power8.

Below are the numbers we are observing for SHA-256 and SHA-512 using built-ins. The numbers are not that impressive. Even OpenSSL's numbers seems relatively dull. We expect Power8's SHA-256 to be somewhere between 2 to 6 cpb; and SHA-512 between 4 to 8 cpb (but it is only a guess).

According to IBM's [Performance Optimization and Tuning Techniques for IBM Power Systems Processors Including IBM POWER8](https://www.redbooks.ibm.com/redbooks/pdfs/sg248171.pdf), p. 182: *"[POWER8] in-core SHA instructions can increase speed, as compared with equivalent JIT-generated code"*. If performance goals are only to outperform JIT, then this might be the best we can do.

# Benchmarks

The speedups can be tricky to measure, but concrete numbers are availble from Jack Lloyd's Botan. The relative speedups using a three second benchmark under the command `./botan speed --msec=3000 SHA-1 SHA-224 SHA-256` are as follows. The measurements were taken from a Intel Celeron J3455, and an ARMv8 LeMaker HiKey.

## Intel SHA

The following tests were run on a machine with a Celeron J3455 at 1.5 GHz (burst at 2.2 GHz). The machine has an ASUS J3455M-E motherboard, which was one of the first Goldmont's available.

### GCC 7.3.1

```
$ ./botan speed --msec=3000 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512
SHA-160 hash buffer size 1024 bytes: 887.435 MiB/sec 1.61 cycles/byte (2662.31 MiB in 3000.00 ms)
SHA-224 hash buffer size 1024 bytes: 443.480 MiB/sec 3.22 cycles/byte (1330.44 MiB in 3000.00 ms)
SHA-256 hash buffer size 1024 bytes: 443.614 MiB/sec 3.22 cycles/byte (1330.84 MiB in 3000.00 ms)
SHA-384 hash buffer size 1024 bytes: 122.228 MiB/sec 11.69 cycles/byte (366.68 MiB in 3000.00 ms)
SHA-512 hash buffer size 1024 bytes: 119.733 MiB/sec 11.93 cycles/byte (359.20 MiB in 3000.00 ms)
```

### Clang 5.0.1

```
$ ./botan speed --msec=3000 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512
SHA-160 hash buffer size 1024 bytes: 912.617 MiB/sec 1.57 cycles/byte (2737.85 MiB in 3000.00 ms)
SHA-224 hash buffer size 1024 bytes: 447.320 MiB/sec 3.20 cycles/byte (1341.96 MiB in 3000.00 ms)
SHA-256 hash buffer size 1024 bytes: 447.315 MiB/sec 3.20 cycles/byte (1341.94 MiB in 3000.00 ms)
SHA-384 hash buffer size 1024 bytes: 124.250 MiB/sec 11.50 cycles/byte (372.75 MiB in 3000.01 ms)
SHA-512 hash buffer size 1024 bytes: 124.248 MiB/sec 11.50 cycles/byte (372.74 MiB in 3000.00 ms)
```

## ARM SHA

The following tests were run on a machine with a Kirin 620 SoC and octa-core ARM Cortex-A53 at 1.2 GHz. The machine was one of the first Aarch64's with crypto extensions available.

### GCC 4.9.2

```
$ ./botan speed --msec=3000 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512
SHA-160 hash buffer size 1024 bytes: 664.520 MiB/sec (1993.561 MiB in 3000.001 ms)
SHA-224 hash buffer size 1024 bytes: 599.788 MiB/sec (1799.363 MiB in 3000.000 ms)
SHA-256 hash buffer size 1024 bytes: 599.463 MiB/sec (1798.391 MiB in 3000.001 ms)
SHA-384 hash buffer size 1024 bytes: 188.142 MiB/sec (564.426 MiB in 3000.001 ms)
SHA-512 hash buffer size 1024 bytes: 188.017 MiB/sec (564.051 MiB in 3000.001 ms)
```

### Clang 3.7

To be determined.

## Power8 SHA

The following tests were run on GCC112 from the compile farm, which is ppc64-le at 3.4 GHz.

### GCC 7.2.0

```
$ ./botan speed --msec=3000 --cpu-clock-speed=3400 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512

MD5 hash buffer size 1024 bytes: 236.689 MiB/sec 13.70 cycles/byte (710.07 MiB in 3000.00 ms)
SHA-160 hash buffer size 1024 bytes: 355.444 MiB/sec 9.12 cycles/byte (1066.33 MiB in 3000.00 ms)
SHA-224 hash buffer size 1024 bytes: 250.667 MiB/sec 12.94 cycles/byte (752.00 MiB in 3000.00 ms)
SHA-256 hash buffer size 1024 bytes: 250.424 MiB/sec 12.95 cycles/byte (751.27 MiB in 3000.00 ms)
SHA-384 hash buffer size 1024 bytes: 327.598 MiB/sec 9.90 cycles/byte (982.79 MiB in 3000.00 ms)
SHA-512 hash buffer size 1024 bytes: 327.507 MiB/sec 9.90 cycles/byte (982.52 MiB in 3000.00 ms)
```
