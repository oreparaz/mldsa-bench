#!/usr/bin/env bash
# Sweep every verify variant at ITERS=0,1,11 under qemu-system-arm with the
# cyclebench-m4 plugin attached. Per-iter cost = (N(iters=11) - N(iters=1)) / 10
# — that nulls out program startup, the FPU enable, .bss zero, and the trailing
# semihosting writes/exit (all of which sum to 178 instructions).
#
# Pipe to: tee results.txt
set -euo pipefail
cd "$(dirname "$0")"

variants=(mldsa44 mldsa65 mldsa87 p256-m p256-oreparaz)
declare -A insns_0 insns_1 insns_11 digests

for v in "${variants[@]}"; do
    for n in 0 1 11; do
        out=$(make count BENCH="$v" ITERS="$n" 2>&1 | tail -2)
        digest=$(echo "$out" | head -1)
        insns=$(echo "$out" | tail -1 | awk '{print $NF}')
        case "$n" in
            0)  insns_0[$v]=$insns ;;
            1)  insns_1[$v]=$insns; digests[$v]=$digest ;;
            11) insns_11[$v]=$insns ;;
        esac
    done
done

printf "\n%-16s %12s %12s %12s %14s\n" \
    bench iters=0 iters=1 iters=11 per-iter
printf "%-16s %12s %12s %12s %14s\n" \
    ---------------- ------------ ------------ ------------ --------------
for v in "${variants[@]}"; do
    per_iter=$(( (insns_11[$v] - insns_1[$v]) / 10 ))
    printf "%-16s %12s %12s %12s %14s\n" \
        "$v" "${insns_0[$v]}" "${insns_1[$v]}" "${insns_11[$v]}" "$per_iter"
done
