# mldsa-bench — ML-DSA vs P-256 verify cost on Cortex-M4

A small harness that measures the cost of signature verification for
ML-DSA (FIPS 204) and ECDSA P-256, expressed in **instructions retired**
on a Cortex-M4 ISA. The numbers cover ten implementations plus a
**custom secure-boot ML-DSA-44 verifier** progressively optimized through
ten versions (5.22× faster than the pqm4 m4f baseline).

| Library | Algorithm | Notes |
|---|---|---|
| [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native) | ML-DSA-44 / 65 / 87 | C90 portable backend (no Cortex-M asm); built `-O3` |
| [mupq/pqm4](https://github.com/mupq/pqm4) (`m4f`) | ML-DSA-44 / 65 / 87 | Hand-tuned Cortex-M4 asm (NTT, pointwise, Keccak f1600); built `-O3` |
| [mpg/p256-m](https://github.com/mpg/p256-m) | ECDSA P-256 verify | Hand-tuned Cortex-M UMAAL asm for the 32×32+32+32 inner loop |
| [oreparaz/p256](https://github.com/oreparaz/p256) | ECDSA P-256 verify (incl. SHA-256) | Pure C distillate of BearSSL; verifies raw messages |

All cross-compiled with `arm-none-eabi-gcc 13.2.1` for Cortex-M4
(Thumb-2, FPv4-SP-d16, hard-float, `__ARM_FEATURE_DSP`) and run end-to-end
under `qemu-system-arm 11.0.0 -M mps2-an386` with the
[cyclebench-m4](https://github.com/oreparaz/cyclebench-m4) TCG plugin
attached. The `mldsa-pqm4-*` builds verify the **same** `(pk, sig, msg, ctx)`
test vectors that `mldsa-native` ships, confirming FIPS-204 interop at the
byte level.

## Results

Instructions retired per `verify()` call, computed as
`(N(iters=11) − N(iters=1)) / 10` to subtract program startup/exit:

| Implementation                                          | `-O3` (insns)   | `-O2` (insns)   | vs ML-DSA-44 (mldsa-native, O3) |
|---------------------------------------------------------|----------------:|----------------:|-------------------:|
| **ML-DSA-44** — mldsa-native (C-only)                   | **2,120,554**   | 2,187,838       | 1.00× |
| **ML-DSA-65** — mldsa-native (C-only)                   | **3,547,907**   | 3,666,128       | 1.67× |
| **ML-DSA-87** — mldsa-native (C-only)                   | **6,077,821**   | 6,281,538       | 2.87× |
| **ML-DSA-44** — pqm4 m4f (M4-asm NTT + Keccak)          | **1,270,759**   | 1,294,637       | **0.60×** |
| **ML-DSA-65** — pqm4 m4f (M4-asm NTT + Keccak)          | **2,161,418**   | 2,215,174       | **1.02×** |
| **ML-DSA-87** — pqm4 m4f (M4-asm NTT + Keccak)          | **3,758,581**   | 3,855,386       | **1.77×** |
| **P-256 ECDSA** — oreparaz/p256 (pure C, incl. SHA-256) | **8,122,459** † | 11,828,264      | 3.83× |
| **P-256 ECDSA** — p256-m (M4 UMAAL asm)                 | **12,320,435** ‡| 15,945,579      | 5.81× |

† Includes one SHA-256 compress block (~3,500 insns) because oreparaz/p256
hashes the message internally.
‡ Excludes SHA-256 — p256-m takes the digest pre-computed.

### Headline numbers

- **ML-DSA verify is faster than ECDSA P-256 verify on Cortex-M4, at every
  security level**, even when the ML-DSA implementation is pure C and the
  P-256 implementation has hand-tuned M4 asm.
- The **pqm4** M4-asm backend gives ML-DSA a consistent **~1.65× speedup**
  over mldsa-native's pure-C path across all three parameter sets, putting
  ML-DSA-44 verify at **~1.27M instructions** — almost an order of magnitude
  cheaper than the cheapest P-256 verify we measured.
- `-O3` is meaningfully faster than `-O2` for the C-heavy P-256 codes
  (-29% for p256-m, -31% for oreparaz/p256), but only marginally for ML-DSA
  (-3% for mldsa-native, -2% for pqm4) — most ML-DSA hot loops are already
  hand-unrolled in asm or in tight C with explicit register hints.

### Raw output of the sweep (-O3)

```
bench                   iters=0      iters=1     iters=11       per-iter
------------------ ------------ ------------ ------------ --------------
mldsa44                     178      2120733     23326279        2120554
mldsa65                     178      3548086     39027158        3547907
mldsa87                     178      6078000     66856216        6077821
mldsa-pqm4-44               178      1270938     13978534        1270759
mldsa-pqm4-65               178      2161597     23775783        2161418
mldsa-pqm4-87               178      3758760     41344576        3758581
p256-m                      178     12320611    135524968       12320435
p256-oreparaz               178      8122635     89347231        8122459
```

Reproduce: `cd bench && OPT=-O3 ./run_sweep.sh` (or `OPT=-O2 …`).

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
~1.5–3× depending on flash wait states and memory layout. As a
sanity-check: published silicon numbers for p256-m on STM32F411 land at
~31M cycles per verify, vs our 12.3M instructions — about 2.5× ratio,
which is the expected wait-state / branch-penalty bloat.

Sanity-check for pqm4 too: their published benchmarks list ML-DSA-44
verify at ~1.65M cycles on an STM32F407 (slightly different M4, with
flash wait states), vs our 1.27M instructions — 1.3× ratio. Consistent.

## A secure-boot–specialized ML-DSA-44 verifier (10× progressive iterations)

The numbers above measure off-the-shelf libraries. For **secure boot**, the
public key is fixed at provisioning time and the verifier sees:
- pk = 1312 bytes, identical every boot
- ctx = empty
- msg = a 32-byte SHA-256 of the firmware image

Several pieces of pqm4's verify are deterministic functions of pk only,
so they can be **precomputed once at setup** and reused across every boot.
Combined with verify-side specializations that exploit
all-public-data semantics, `bench/sb-mldsa44-v*/` walks through ten
progressively faster verifiers. **Each version was confirmed to verify
the same FIPS-204 test vector** (generated by `tools/gen_sb_testvec`,
which signs a 32-byte hash using mldsa-native's portable C90 ML-DSA-44
under a deterministic keypair).

| Version | Optimization | Insns/verify | Speedup vs v1 | Delta vs prev |
|--------:|:-------------|-------------:|--------------:|--------------:|
| v1 | pqm4 m4f, secure-boot inputs (msg=32B, ctx=∅) — baseline | **1,261,555** | 1.00× | — |
| v2 | precompute `A_NTT[K][L]` (skip ExpandA) | **410,292** | 3.07× | −67.5% |
| v3 | + precompute `t1_shifted_NTT[K]` (skip unpack/shiftL/NTT of t1) | **368,019** | 3.43× | −10.3% |
| v4 | + precompute `tr_pk = SHAKE256(pk, 64)` (skip 1312B absorb in mu) | **268,420** | 4.70× | −27.1% |
| v5 | + pre-warmed Keccak state with `tr_pk ‖ 0x00 ‖ 0x00` absorbed | **267,944** | 4.71× | −0.2% |
| v6 | unpack hint polys once (one walk over hint encoding, not K) | **265,460** | 4.75× | −0.9% |
| v7 | fuse `caddq + use_hint + polyw1_pack` into one pass per row | **256,559** | 4.92× | −3.4% |
| v8 | fuse `unpack_sig_z + polyvecl_chknorm` (one scan over z) | **247,788** | 5.09× | −3.4% |
| v9 | skip `poly_reduce` before `invntt_tomont` (range still in spec) | **242,376** | 5.20× | −2.2% |
| v10 | drive c̃′ Keccak with raw `StateXORBytes`/`Permute` (no inc API) | **241,756** | 5.22× | −0.3% |

The 1,019,799 instructions saved are dominated by the **`A` precompute** (v2,
~850 k) and **`tr_pk` precompute** (v4, ~100 k). All other phases together
contribute ~70 k — useful, but a long tail.

How is precompute amortized? Each `bench/sb-mldsa44-vN/bench_main.c` runs
`sb_vN_precompute(sb_pk)` once before the timed loop. The sweep measures
`(N(ITERS=11) − N(ITERS=1)) / 10`, so the precompute cost shows up only in
the `iters=0` and `iters=1` columns (visible as the ~860k-1M baseline jump
between v1 and v2 in `results-O3.txt`) and is fully absorbed by the
subtraction. In a real secure-boot deployment, precompute runs once at the
factory and lives in flash, with verify reading from flash on every boot.

What does "do not cheat" mean here? The verifier still:
- Reads the actual `(sig, pk, msg)` bytes and computes mu, the challenge
  polynomial, `Az − ct·2^d`, applies the hint, and recomputes c̃′ — i.e.
  follows FIPS 204 Algorithm 8 step-for-step.
- Returns the actual byte-equality result of c̃ vs c̃′ — no hardcoded "pass".
- Performs the spec-mandated norm check on z (`|z| < γ₁−β`) and validates
  the hint-encoding monotonicity (we just fold both checks into a single
  pass over the input bytes).
- Uses pqm4's hand-tuned M4 asm for the lattice primitives (NTT, pointwise
  Mont, Keccak f1600) — these were never replaced.
- Only precomputes data that is a deterministic function of `pk`, which
  is genuinely fixed at provisioning time in a secure-boot deployment.

What's deferred for later: writing custom M4 asm to fuse the c*t1_ntt
pointwise mult into a `pointwise_sub_montgomery` (would skip one stack
pass over the 1 KB polynomial); an attempted v8 that XOR'd the packed w1
bytes directly into the Keccak state's rate hit a compiler-level
write-barrier issue with `KeccakF1600_StatePermute` that I couldn't
isolate in the time budget — v10 reaches most of the same savings via
chunked `StateXORBytes` calls.

### Putting v10 in the cross-library table

Compared against the off-the-shelf benchmarks at the top:

| Verify implementation                                  | Insns retired (M4) | Ratio vs sb-v10 |
|--------------------------------------------------------|-------------------:|---------------:|
| **sb-mldsa44-v10** (secure-boot specialized)           | **241,756**        | 1.00× |
| pqm4 m4f ML-DSA-44 (generic, M4 asm)                    | 1,270,759          | 5.26× |
| mldsa-native ML-DSA-44 (portable C90)                   | 2,120,554          | 8.77× |
| oreparaz/p256 ECDSA (pure C, incl. SHA-256)             | 8,122,459          | 33.60× |
| p256-m ECDSA (M4 UMAAL asm)                             | 12,320,435         | 50.96× |

**A boot loader using sb-v10 to verify its firmware image takes ~242 k
M4 instructions per signature** — roughly **34× fewer** than a pure-C P-256
verify and **51× fewer** than p256-m. Even compared to itself, ML-DSA-44
verify becomes "free" on M4 once pk-derived data is precomputed.

## Important caveats

1. **mldsa-native has no Cortex-M backend.** Its asm targets are AArch64
   and x86-64; the M4 numbers above are pure C90. The pqm4 M4-asm port
   exists *because* C-only ML-DSA leaves ~40% on the floor on M4.
2. **The two P-256 implementations are not strictly comparable to each
   other.** p256-m takes a pre-computed hash; oreparaz/p256 hashes the
   message itself. The bench includes the SHA-256 of a 3-byte message in
   oreparaz/p256's number (~3,500 insns), which is ~0.04% of the total.
3. **pqm4 ML-DSA verifies the *same* mldsa-native test vectors** byte-for-
   byte — they're both FIPS 204 ML-DSA. The bench wires the `(pk, sig,
   msg, ctx)` arrays from `mldsa-native/.../expected_test_vectors.h` into
   both verify paths so the comparison is exactly apples-to-apples at the
   I/O level.
4. **Verify-only.** ML-DSA's signing path is *much* slower than verify
   (rejection sampling). These numbers should not be used to compare
   overall handshake cost.

## Repo layout

```
bench/
  Makefile                                 # builds 18 M4 ELFs (8 off-the-shelf + 10 sb-v*)
  run_sweep.sh                             # ITERS=0,1,11 across every variant
  common/                                  # M4 startup, semihosting, link script
  mldsa44/  mldsa65/  mldsa87/             # mldsa-native, one Makefile rule each
  mldsa-pqm4-44/  mldsa-pqm4-65/  mldsa-pqm4-87/   # pqm4 m4f backend
  p256-m/                                  # mpg/p256-m
  p256-oreparaz/                           # oreparaz/p256
  sb-mldsa44-v1/ … sb-mldsa44-v10/         # secure-boot specializations, one dir per version
  build/                                   # output ELFs (gitignored)
tools/
  gen_sb_testvec.c                         # host-side (pk, sig, hash) generator using mldsa-native
  Makefile                                 # `make sb_testvec_v1` writes bench/sb-mldsa44-v1/testvec.h

cyclebench-m4/   mldsa-native/   pqm4/   p256-m/   p256/   # populated by setup.sh
results-O3.txt   results-O2.txt   # last sweep outputs
```

## Reproducing

```bash
# 1. Toolchain (Ubuntu 24.04)
sudo apt-get install -y \
    gcc-arm-none-eabi binutils-arm-none-eabi \
    libglib2.0-dev ninja-build pkg-config python3-venv

# 2. Clone upstream repos at pinned SHAs (~30s, ~25 MB)
./setup.sh

# 3. Build the plugin-enabled QEMU 11.0.0 (one-shot, ~30s)
cd cyclebench-m4 && make qemu && cd ..

# 4. Build the instruction-counter plugin
make -C cyclebench-m4/plugin

# 5. Run the sweep
cd bench && OPT=-O3 ./run_sweep.sh
cd bench && OPT=-O2 ./run_sweep.sh
```

## Build flags

`bench/Makefile` uses:

```
$(OPT) -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
-ffreestanding -nostartfiles
-ffunction-sections -fdata-sections
-Wl,--gc-sections
```

with `OPT` defaulting to `-O3`. The `-mcpu=cortex-m4` flag enables
`__ARM_FEATURE_DSP`, which selects:

- p256-m's 1-instruction UMAAL inner-multiply path
- pqm4's M4-asm NTT and pointwise-multiply (the `m4f` directory tag
  implies "M4 with FPU"; the FPU isn't used for ML-DSA but enabling it
  unlocks the same `-mcpu`).

`mldsa-native` and `oreparaz/p256` have no Cortex-M asm and pick up only
the compiler's auto-scheduling.

## License

This harness is GPL-2.0-or-later (inherited from cyclebench-m4 and QEMU's
plugin API). Upstream crypto libraries keep their own licenses:
Apache-2.0 / ISC / MIT for mldsa-native; Apache-2.0 / CC0-1.0 for pqm4;
Apache-2.0 for p256-m; MIT for oreparaz/p256.
