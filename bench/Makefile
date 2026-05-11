# Top-level bench Makefile.
#
# Builds bare-metal Cortex-M4 ELFs for several signature-verification
# variants, then runs them under qemu-system-arm with the cyclebench-m4
# instruction-counting plugin attached.
#
#   make count BENCH=mldsa44                # default ITERS=1
#   make count BENCH=mldsa44 ITERS=1
#   make count BENCH=mldsa44 ITERS=11       # for per-iter from N1, N11
#   make count BENCH=p256-m  ITERS=10
#   make all-baselines        # baseline+1-iter for every variant
#   make table                # full sweep: baseline + small iter count + larger
#
# Cycle-bench instruments instructions retired on a real Cortex-M4 ISA via
# the QEMU mps2-an386 model. The number we report is instructions retired
# per verify(), measured as (N(iters=K) - N(iters=0)) / K.

# ---- toolchain / qemu / plugin ----
CC_M4      ?= arm-none-eabi-gcc
SIZE_M4    ?= arm-none-eabi-size
OBJDUMP_M4 ?= arm-none-eabi-objdump

REPO_ROOT  := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CB_DIR     := $(REPO_ROOT)/cyclebench-m4
QEMU       ?= $(CB_DIR)/qemu/build/qemu-system-arm
PLUGIN     := $(CB_DIR)/plugin/libinsn_count.so

# ---- common M4 flags ----
# OPT defaults to -O3 ("optimized for speed"). Override with OPT=-O2 etc.
OPT ?= -O3
M4FLAGS_COMMON = \
    -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard \
    -ffreestanding -nostartfiles $(OPT) -g -Wall -Wextra \
    -ffunction-sections -fdata-sections \
    -Wno-type-limits \
    -DBAREMETAL -I$(REPO_ROOT)/bench/common

M4LDFLAGS = -T $(REPO_ROOT)/bench/common/link.ld \
            -Wl,--gc-sections -Wl,--build-id=none -lm

# ---- shared M4 startup objects ----
COMMON_SRCS = \
    $(REPO_ROOT)/bench/common/startup.c \
    $(REPO_ROOT)/bench/common/semihost.c \
    $(REPO_ROOT)/bench/common/bench_io_baremetal.c

ITERS ?= 1
BUILD ?= build

# ---- ml-dsa monolithic build ----
MLD_DIR := $(REPO_ROOT)/mldsa-native/examples/monolithic_build/mldsa_native
MLD_SRC := $(MLD_DIR)/mldsa_native.c
MLD_VECTORS := $(REPO_ROOT)/mldsa-native/examples/monolithic_build/expected_test_vectors.h
MLD_VECTORS_DIR := $(dir $(MLD_VECTORS))
MLD_FLAGS = -I$(MLD_DIR) -I$(MLD_VECTORS_DIR) \
            -Wno-pedantic -Wno-sign-conversion -Wno-conversion \
            -Wno-shadow -Wno-redundant-decls -Wno-missing-prototypes

# ---- p256-m (Manuel Pégourié-Gonnard) ----
P256M_SRC := $(REPO_ROOT)/p256-m/p256-m.c
P256M_DIR := $(REPO_ROOT)/p256-m
P256M_FLAGS = -I$(P256M_DIR) -Wno-pedantic -Wno-unused-parameter

# ---- p256 (oreparaz, BearSSL distillate) ----
P256_SRC := $(REPO_ROOT)/p256/p256.c
P256_DIR := $(REPO_ROOT)/p256
P256_FLAGS = -I$(P256_DIR) -Wno-pedantic -Wno-unused-parameter \
             -Wno-sign-compare

# ---- pqm4 ML-DSA (m4f-asm-tuned Cortex-M4 backend) ----
# The verify path pulls in: every .c/.S in crypto_sign/ml-dsa-XX/m4f/ plus
# the shared symcrypto sources (fips202.c + keccakf1600.S). --gc-sections
# drops the sign/keygen-only code (which references randombytes) at link
# time.
PQM4 := $(REPO_ROOT)/pqm4
PQM4_SYMCRYPTO := \
    $(PQM4)/mupq/common/fips202.c \
    $(PQM4)/common/keccakf1600.S
PQM4_FLAGS = -Wno-pedantic -Wno-sign-conversion -Wno-conversion \
             -Wno-shadow -Wno-redundant-decls -Wno-missing-prototypes \
             -Wno-unused-function -Wno-unused-but-set-variable \
             -I$(PQM4)/mupq/common -I$(MLD_VECTORS_DIR)
# Sources for each parameter set are globbed from the m4f directory.
PQM4_MLDSA44_DIR := $(PQM4)/crypto_sign/ml-dsa-44/m4f
PQM4_MLDSA65_DIR := $(PQM4)/crypto_sign/ml-dsa-65/m4f
PQM4_MLDSA87_DIR := $(PQM4)/crypto_sign/ml-dsa-87/m4f
PQM4_MLDSA44_SRCS := $(wildcard $(PQM4_MLDSA44_DIR)/*.c) \
                     $(wildcard $(PQM4_MLDSA44_DIR)/*.S) \
                     $(wildcard $(PQM4_MLDSA44_DIR)/*.s)
PQM4_MLDSA65_SRCS := $(wildcard $(PQM4_MLDSA65_DIR)/*.c) \
                     $(wildcard $(PQM4_MLDSA65_DIR)/*.S) \
                     $(wildcard $(PQM4_MLDSA65_DIR)/*.s)
PQM4_MLDSA87_SRCS := $(wildcard $(PQM4_MLDSA87_DIR)/*.c) \
                     $(wildcard $(PQM4_MLDSA87_DIR)/*.S) \
                     $(wildcard $(PQM4_MLDSA87_DIR)/*.s)

# ============================================================
# per-bench ELF rules
#
# ITERS gets baked in at compile time via -DBENCH_ITERS, so the ELF needs
# to be rebuilt every time ITERS changes. We force this by having each
# recipe `rm -f` its target first — the build is sub-second for the p256
# variants and a few seconds for ml-dsa (one big TU).
# ============================================================

SB_VERSIONS := v1 v2 v3 v4 v5 v6 v7 v8 v9
SB_TARGETS  := $(addprefix sb-mldsa44-,$(SB_VERSIONS))
SB_ELFS     := $(addsuffix .elf,$(addprefix $(BUILD)/,$(SB_TARGETS)))

.PHONY: all \
        mldsa44 mldsa65 mldsa87 \
        mldsa-pqm4-44 mldsa-pqm4-65 mldsa-pqm4-87 \
        p256-m p256-oreparaz \
        $(SB_TARGETS) \
        $(BUILD)/mldsa44.elf $(BUILD)/mldsa65.elf $(BUILD)/mldsa87.elf \
        $(BUILD)/mldsa-pqm4-44.elf $(BUILD)/mldsa-pqm4-65.elf $(BUILD)/mldsa-pqm4-87.elf \
        $(BUILD)/p256-m.elf $(BUILD)/p256-oreparaz.elf \
        $(SB_ELFS)
all: mldsa44 mldsa65 mldsa87 mldsa-pqm4-44 mldsa-pqm4-65 mldsa-pqm4-87 p256-m p256-oreparaz $(SB_TARGETS)

mldsa44:        $(BUILD)/mldsa44.elf
mldsa65:        $(BUILD)/mldsa65.elf
mldsa87:        $(BUILD)/mldsa87.elf
mldsa-pqm4-44:  $(BUILD)/mldsa-pqm4-44.elf
mldsa-pqm4-65:  $(BUILD)/mldsa-pqm4-65.elf
mldsa-pqm4-87:  $(BUILD)/mldsa-pqm4-87.elf
p256-m:         $(BUILD)/p256-m.elf
p256-oreparaz:  $(BUILD)/p256-oreparaz.elf

$(BUILD):
	@mkdir -p $(BUILD)

MLD_CC = $(CC_M4) $(M4FLAGS_COMMON) $(MLD_FLAGS) -DBENCH_ITERS=$(ITERS)

$(BUILD)/mldsa44.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS) PARAM=44)"
	@$(MLD_CC) -DMLD_CONFIG_PARAMETER_SET=44 $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/mldsa44/bench_main.c $(MLD_SRC) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/mldsa65.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS) PARAM=65)"
	@$(MLD_CC) -DMLD_CONFIG_PARAMETER_SET=65 $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/mldsa65/bench_main.c $(MLD_SRC) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/mldsa87.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS) PARAM=87)"
	@$(MLD_CC) -DMLD_CONFIG_PARAMETER_SET=87 $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/mldsa87/bench_main.c $(MLD_SRC) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/mldsa-pqm4-44.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS) DILITHIUM_MODE=2)"
	@$(CC_M4) $(M4FLAGS_COMMON) $(PQM4_FLAGS) -I$(PQM4_MLDSA44_DIR) \
	    -DBENCH_ITERS=$(ITERS) \
	    $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/mldsa-pqm4-44/bench_main.c \
	    $(PQM4_MLDSA44_SRCS) $(PQM4_SYMCRYPTO) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/mldsa-pqm4-65.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS) DILITHIUM_MODE=3)"
	@$(CC_M4) $(M4FLAGS_COMMON) $(PQM4_FLAGS) -I$(PQM4_MLDSA65_DIR) \
	    -DBENCH_ITERS=$(ITERS) \
	    $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/mldsa-pqm4-65/bench_main.c \
	    $(PQM4_MLDSA65_SRCS) $(PQM4_SYMCRYPTO) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/mldsa-pqm4-87.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS) DILITHIUM_MODE=5)"
	@$(CC_M4) $(M4FLAGS_COMMON) $(PQM4_FLAGS) -I$(PQM4_MLDSA87_DIR) \
	    -DBENCH_ITERS=$(ITERS) \
	    $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/mldsa-pqm4-87/bench_main.c \
	    $(PQM4_MLDSA87_SRCS) $(PQM4_SYMCRYPTO) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/p256-m.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS))"
	@$(CC_M4) $(M4FLAGS_COMMON) $(P256M_FLAGS) \
	    -DBENCH_ITERS=$(ITERS) \
	    $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/p256-m/bench_main.c $(P256M_SRC) $(COMMON_SRCS)
	@$(SIZE_M4) $@

$(BUILD)/p256-oreparaz.elf: | $(BUILD)
	@rm -f $@
	@echo "  CC[m4] $@ (ITERS=$(ITERS))"
	@$(CC_M4) $(M4FLAGS_COMMON) $(P256_FLAGS) \
	    -DBENCH_ITERS=$(ITERS) \
	    $(M4LDFLAGS) -o $@ \
	    $(REPO_ROOT)/bench/p256-oreparaz/bench_main.c $(P256_SRC) $(COMMON_SRCS)
	@$(SIZE_M4) $@

# ============================================================
# sb-mldsa44 (secure-boot ML-DSA-44 verify, progressively optimized)
#
# Each version is a separate directory bench/sb-mldsa44-vN/ that supplies
# its own bench_main.c. Versions v1..v6 reuse pqm4's m4f primitives in
# their entirety (linked via $(PQM4_MLDSA44_SRCS) + $(PQM4_SYMCRYPTO));
# versions v7..v8 may pull in additional local .c files via SBV*_EXTRA.
#
# Each version has its own testvec.h with a fresh (pk, sig, hash) tuple
# generated by tools/gen_sb_testvec — but they all share the same vector
# because hash, pk, and sig are functions of a fixed image+seed.
# ============================================================
SB_FLAGS = -Wno-pedantic -Wno-sign-conversion -Wno-conversion \
           -Wno-shadow -Wno-redundant-decls -Wno-missing-prototypes \
           -Wno-unused-function -Wno-unused-but-set-variable \
           -I$(PQM4)/mupq/common -I$(PQM4_MLDSA44_DIR)

define BUILD_SBV
$(BUILD)/sb-mldsa44-$(1).elf: | $(BUILD)
	@rm -f $$@
	@echo "  CC[m4] $$@ (ITERS=$$(ITERS) sb-mldsa44-$(1))"
	@$(CC_M4) $(M4FLAGS_COMMON) $(SB_FLAGS) \
	    -I$(REPO_ROOT)/bench/sb-mldsa44-$(1) \
	    -DBENCH_ITERS=$$(ITERS) \
	    $(M4LDFLAGS) -o $$@ \
	    $(REPO_ROOT)/bench/sb-mldsa44-$(1)/bench_main.c \
	    $$(wildcard $(REPO_ROOT)/bench/sb-mldsa44-$(1)/*_extra.c) \
	    $(PQM4_MLDSA44_SRCS) $(PQM4_SYMCRYPTO) $(COMMON_SRCS)
	@$(SIZE_M4) $$@

sb-mldsa44-$(1): $(BUILD)/sb-mldsa44-$(1).elf
endef

$(foreach v,$(SB_VERSIONS),$(eval $(call BUILD_SBV,$(v))))

# ============================================================
# run targets
# ============================================================
.PHONY: count
count:
	@$(MAKE) -s ITERS=$(ITERS) $(BENCH) > /dev/null
	@$(QEMU) -M mps2-an386 -nographic -no-reboot \
	    -semihosting-config enable=on,target=native \
	    -plugin $(PLUGIN) -d plugin \
	    -kernel $(BUILD)/$(BENCH).elf 2>&1 \
	    | grep -E '^[0-9a-f]+$$|^insns retired'

# Run each variant at ITERS=0 (baseline) and ITERS=1 to verify it works at all.
.PHONY: smoke
smoke:
	@for b in mldsa44 mldsa65 mldsa87 p256-m p256-oreparaz; do \
	    echo "==== $$b ITERS=0 ===="; $(MAKE) -s count BENCH=$$b ITERS=0; \
	    echo "==== $$b ITERS=1 ===="; $(MAKE) -s count BENCH=$$b ITERS=1; \
	done

# Full sweep that the results/ table is generated from.
# Per-iter = (N(ITERS=N) - N(ITERS=0)) / N
.PHONY: table
table:
	@./run_sweep.sh

.PHONY: clean
clean:
	rm -rf $(BUILD)
