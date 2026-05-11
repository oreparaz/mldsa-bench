# mldsa-bench — ML-DSA vs P-256 verify cost on Cortex-M4

A small harness that measures the cost of signature verification for
ML-DSA (FIPS 204) and ECDSA P-256, expressed in **instructions retired**
on a Cortex-M4 ISA. The numbers cover five implementations:

| Library | Algorithm | Notes |
|---|---|---|
| [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native) | ML-DSA-44 / 65 / 87 | C90 portable backend (no Cortex-M asm); built `-O3` |
| [mpg/p256-m](https://github.com/mpg/p256-m) | ECDSA P-256 verify | hand-tuned Cortex-M UMAAL asm for the 32×32+32+32 inner loop |
| [oreparaz/p256](https://github.com/oreparaz/p256) | ECDSA P-256 verify (incl. SHA-256) | pure C distillate of BearSSL; verifies raw messages |

All five are cross-compiled with `arm-none-eabi-gcc 13.2.1` for
Cortex-M4 (Thumb-2, FPv4-SP-d16, hard-float, `__ARM_FEATURE_DSP`)
and run end-to-end under `qemu-system-arm -M mps2-an386` with the
[cyclebench-m4](https://github.com/oreparaz/cyclebench-m4) TCG plugin
attached.

## Results

Instructions retired per `verify()` call, computed as
`(N(iters=11) − N(iters=1)) / 10` to subtract program startup/exit:

| Implementation             | Verify  (insns retired on M4) | Relative to ML-DSA-44 |
|----------------------------|------------------------------:|----------------------:|
| **ML-DSA-44** (mldsa-native, C-only) | **2,120,554** | 1.00× |
| **ML-DSA-65** (mldsa-native, C-only) | **3,547,907** | 1.67× |
| **ML-DSA-87** (mldsa-native, C-only) | **6,077,821** | 2.87× |
| **P-256 ECDSA** (oreparaz/p256, pure C) | **8,122,459** † | 3.83× |
| **P-256 ECDSA** (p256-m, M4 UMAAL asm) | **12,320,435** ‡ | 5.81× |

† Includes one SHA-256 compress block (~3,500 insns) because oreparaz/p256
hashes the message internally.
‡ Excludes SHA-256 — p256-m takes the digest pre-computed.

In one sentence: **ML-DSA verify on a Cortex-M4 is faster than ECDSA P-256
verify across all three security levels** — when measured against C-only
P-256 (oreparaz/p256), ML-DSA-44 is ~3.8× faster and even the largest
parameter set (ML-DSA-87) is ~1.34× faster.

### Raw output of the sweep

```
bench                 iters=0      iters=1     iters=11       per-iter
---------------- ------------ ------------ ------------ --------------
mldsa44                   178      2120733     23326279        2120554
mldsa65                   178      3548086     39027158        3547907
mldsa87                   178      6078000     66856216        6077821
p256-m                    178     12320611    135524968       12320435
p256-oreparaz             178      8122635     89347231        8122459
```

(Reproduce with `cd bench && ./run_sweep.sh`.)

## What is being counted

QEMU's TCG plugin counts **architecturally-retired instructions on a
Cortex-M4 ISA**, not real silicon cycles. It's a tight lower bound on
real cycles, but it ignores:

| Source of extra cycles    | Typical M4 cost |
|---|---|
| Taken branch              | 1–3 cycles (pipeline refill) |
| `LDR` / `STR` (single)    | 2 cycles (1 if pipelined) |
| `LDM` / `STM` of N regs   | 1 + N cycles |
| `UMULL` / `SMULL`         | 3–5 cycles |
| `SDIV` / `UDIV`           | 2–12 cycles |
| `VDIV.F32` / `VSQRT.F32`  | 14 cycles |
| Flash wait states         | depends on MCU |

So **the *ratio* between two implementations is the right number to trust** —
if A retires 40% fewer instructions than B, A is almost certainly faster
on silicon too. For absolute cycle numbers on a real chip, multiply by
~1.5–3× depending on flash wait states and memory layout. (As a
sanity-check: published silicon numbers for p256-m on STM32F411 land at
~31M cycles per verify, vs our 12.3M instructions — about 2.5× ratio,
which is the expected wait-state / branch-penalty bloat.)

## Important caveats

1. **mldsa-native has no Cortex-M4 native backend.** Its ASM backends
   target AArch64 and x86-64; this bench therefore uses its portable
   C90 path. A hand-tuned Cortex-M port (e.g. pqm4's dilithium)
   should beat these numbers, but mldsa-native's own C path is what
   the user gets when they consume the library as-is on an M4.

2. **The two P-256 implementations are not strictly comparable to
   each other.** p256-m takes a pre-computed hash; oreparaz/p256
   hashes the message itself. The bench includes the SHA-256 of a
   3-byte message in oreparaz/p256's number (~3,500 insns), which is
   ~0.04% of the total — small enough to ignore.

3. **All builds use `-O3`** ("optimized for speed"). p256-m at `-Os`
   is roughly the same speed but smaller; mldsa-native and oreparaz/p256
   both speed up modestly at `-O3` over `-O2`.

4. **Verify-only.** ML-DSA's signing path is *much* slower than verify
   (probabilistic rejection sampling). These numbers should not be
   used to compare overall handshake cost.

5. **One test vector each.** ML-DSA verify cost is essentially data-
   independent (no rejection on the verify side), so a single vector
   suffices.

## Repo layout

```
bench/
  Makefile             # builds five M4 ELFs, runs them under qemu+plugin
  run_sweep.sh         # ITERS=0,1,11 across every variant; prints the table
  common/              # M4 startup, semihosting, link script (from cyclebench-m4)
  mldsa44/  mldsa65/  mldsa87/   # one bench_main.c each; differs only in
                                 # MLD_CONFIG_PARAMETER_SET
  p256-m/                        # bench against mpg/p256-m
  p256-oreparaz/                 # bench against oreparaz/p256
  build/                         # output ELFs (gitignored)

cyclebench-m4/        # upstream harness (vendored as submodule-ish clone)
mldsa-native/         #   "
p256-m/               #   "
p256/                 #   "
results.txt           # rendered output of run_sweep.sh, captured for the
                      # version of toolchain/qemu in this repo
```

## Reproducing

```bash
# 1. Toolchain (Ubuntu 24.04)
sudo apt-get install -y \
    gcc-arm-none-eabi binutils-arm-none-eabi \
    libglib2.0-dev ninja-build pkg-config python3-venv

# 2. Build the plugin-enabled QEMU 11.0.0 (one-shot, ~30s)
cd cyclebench-m4 && make qemu && cd ..

# 3. Build the instruction-counter plugin
make -C cyclebench-m4/plugin

# 4. Run the sweep
cd bench && ./run_sweep.sh
```

## Build flags

`bench/Makefile` uses:

```
-O3 -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
-ffreestanding -nostartfiles
-ffunction-sections -fdata-sections
-Wl,--gc-sections
```

For p256-m, `-mcpu=cortex-m4` enables `__ARM_FEATURE_DSP`, which selects
the 1-instruction UMAAL inner-multiply path in p256-m.c. ML-DSA-native and
oreparaz/p256 have no Cortex-M asm and pick up only the compiler's
auto-scheduling.

## License

This harness is under GPL-2.0-or-later (inherited from cyclebench-m4 and
QEMU's plugin API). Upstream crypto libraries keep their own licenses
(Apache-2.0 / ISC / MIT for mldsa-native; Apache-2.0 for p256-m; MIT for
oreparaz/p256).
