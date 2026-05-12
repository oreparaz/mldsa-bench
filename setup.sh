#!/usr/bin/env bash
# setup.sh — clone upstream repos at the SHAs this bench was built against.
# Run once after a fresh git clone of mldsa-bench. The clones are gitignored
# so this repo stays small.
set -euo pipefail
cd "$(dirname "$0")"

clone() {  # clone url sha dir
    local url=$1 sha=$2 dir=$3
    if [ ! -d "$dir/.git" ]; then
        git clone "$url" "$dir"
    fi
    (cd "$dir" && git fetch --depth=1 origin "$sha" 2>/dev/null || true
     git -c advice.detachedHead=false checkout "$sha")
}

clone https://github.com/oreparaz/cyclebench-m4.git \
      4869ae0f1e9845066c40500a27b5cf0e3f3c242c \
      cyclebench-m4
clone https://github.com/pq-code-package/mldsa-native.git \
      e49cab64c4fb79bd7a195dfd3580f78f50ea6863 \
      mldsa-native
clone https://github.com/mpg/p256-m.git \
      44af59e0cff5d3b1d653bc333814077ef830e1bd \
      p256-m
clone https://github.com/oreparaz/p256.git \
      d7a8c42ddf72ddbd6186bb28d19a853e7deeb333 \
      p256
clone https://github.com/mupq/pqm4.git \
      a24bb4b662016968c19f5e6a0719c9ad530f0286 \
      pqm4

# pqm4 carries its shared sources (fips202, keccakf1600 asm) in a submodule.
(cd pqm4 && git submodule update --init --recursive --depth=1) >/dev/null

clone https://github.com/FasterKyberDilithiumM4/FasterKyberDilithiumM4.git \
      daafc401da7d94e983552cbc3ffbde7df9f70c9d \
      FasterKyberDilithiumM4

echo
echo "Next: build the plugin-enabled QEMU 11.0.0 and the TCG plugin:"
echo "  (cd cyclebench-m4 && make qemu) && make -C cyclebench-m4/plugin"
echo "Then run the sweep:"
echo "  (cd bench && OPT=-O3 ./run_sweep.sh)"
echo "  (cd bench && OPT=-O2 ./run_sweep.sh)"
