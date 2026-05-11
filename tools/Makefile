# Build host-side tools used to seed the benches.
#
#   make gen_sb_testvec      # builds the generator
#   make sb_testvec_v1       # runs it; writes bench/sb-mldsa44-v1/testvec.h

REPO_ROOT  := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
MLD_DIR    := $(REPO_ROOT)/mldsa-native/examples/monolithic_build/mldsa_native
RNG_DIR    := $(REPO_ROOT)/mldsa-native/examples/monolithic_build/test_only_rng

CFLAGS_HOST := -O2 -Wall -Wextra \
               -Wno-pedantic -Wno-sign-conversion -Wno-conversion \
               -Wno-shadow -Wno-redundant-decls -Wno-missing-prototypes \
               -I$(MLD_DIR) -I$(RNG_DIR) \
               -DMLD_CONFIG_PARAMETER_SET=44

.PHONY: all clean
all: gen_sb_testvec

gen_sb_testvec: gen_sb_testvec.c
	$(CC) $(CFLAGS_HOST) -o $@ \
	    gen_sb_testvec.c \
	    $(MLD_DIR)/mldsa_native.c \
	    $(RNG_DIR)/notrandombytes.c

.PHONY: sb_testvec_v1
sb_testvec_v1: gen_sb_testvec
	./gen_sb_testvec $(REPO_ROOT)/bench/sb-mldsa44-v1/testvec.h
	@head -3 $(REPO_ROOT)/bench/sb-mldsa44-v1/testvec.h

clean:
	rm -f gen_sb_testvec
