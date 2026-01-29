# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
#############################################
# Architecture and Toolchain Configuration  #
#############################################
SUPPORTED_ARCHS = arm-m4 risc-v

ARCH ?= arm-m4
ifeq ($(ARCH), risc-v)
	AS         := riscv64-unknown-elf-as
	AR         := riscv64-unknown-elf-ar
	CC         := riscv64-unknown-elf-gcc
	LD         := riscv64-unknown-elf-ld
	OBJDUMP    := riscv64-unknown-elf-objdump
	OBJCOPY    := riscv64-unknown-elf-objcopy
	ASFLAGS    = --warn --fatal-warnings -march=rv32im -mabi=ilp32
	CCFLAGS    = -Wall -g -O2 -ffreestanding -march=rv32im -mabi=ilp32
	LDFLAGS    = -nostdlib -T test.ld
	JASMINCFLAGS = -arch risc-v
else ifeq ($(ARCH), arm-m4)
	AS         := arm-none-eabi-as
	AR         := arm-none-eabi-ar
	CC         := arm-none-eabi-gcc
	LD         := arm-none-eabi-ld
	OBJDUMP    := arm-none-eabi-objdump
	OBJCOPY    := arm-none-eabi-objcopy
	ASFLAGS    = --warn --fatal-warnings -mcpu=cortex-m4
	CCFLAGS    = -Wall -g -O2 -ffreestanding -mcpu=cortex-m4 -mlittle-endian -mthumb -mfloat-abi=soft -mfpu=fpv4-sp-d16 -funroll-loops -fpeel-loops
	LDFLAGS    = -nostdlib -T test.ld
	JASMINCFLAGS = -arch arm-m4
else
	$(error unsupported ARCH)
endif

JASMINC ?= jasminc


#############################################
# Parameter Lists                           #
#############################################
DEGREE_VALUES                   := 1 2 3
FAULTS_VALUES                   := 0 1 2 3
NUM_SECRETS_PER_ENCODING_VALUES := 1
OPT_FROBENIUS_VALUES            := 0 1
OPT_ZENC_VALUES                 := 0 1
NUM_INJECTED_FAULTS_VALUES      := 0 1 2 3 4 5
NUM_FAULT_EXPERIMENTS 			?= 100000
SET_ZERO_FAULTS					?= 0
PROCESS_ID                      ?= 0
FAULT_LAOLA						?= 0

#############################################
# Output directory                          #
#############################################
OUTDIR := build_p$(PROCESS_ID)
POLY_SETUP_DIR := build_poly_masking_parameters
.PHONY: prepare_outputs
prepare_outputs:
	@mkdir -p $(OUTDIR)
	@mkdir -p $(POLY_SETUP_DIR)

#############################################
# Global Macro Definitions                  #
#############################################
SOURCES = $(wildcard src/*.s) \
          $(filter-out src/poly_masked_sbox.c, \
          $(filter-out src/random_bytes.c, \
          $(filter-out src/main.c, \
          $(filter-out src/poly_masking_parameters_%.c, \
          $(wildcard src/*.c))))) \
          $(wildcard src/*.jazz)
OBJS    = $(filter-out $(OUTDIR)/poly_masking_parameters_%.c.o, $(filter-out %.jazz.o, $(SOURCES:$(OUTDIR)/=.o))) \
          $(patsubst %.jazz, $(OUTDIR)/%.jazz.s.o, $(wildcard src/*.jazz))

#############################################
# Auto-Generated Targets (Internal Loops)   #
#############################################
# Define per-config build rule
define BUILD_SINGLE_CONFIG
$(eval CCFLAGS_d$(1)_e$(2)_k$(3)_f$(4)_z$(5)_i$(6) := -DDEGREE=$(1) -DFAULTS=$(2) -DNUM_SECRETS_PER_ENCODING=$(3) -DOPT_FROBENIUS=$(4) -DOPT_ZENC=$(5) -DNUM_INJECTED_FAULTS=$(6) -DNUM_FAULT_EXPERIMENTS=$(NUM_FAULT_EXPERIMENTS) -DSET_ZERO_FAULTS=$(SET_ZERO_FAULTS) -DPROCESS_ID=$(PROCESS_ID) -DFAULT_LAOLA=$(FAULT_LAOLA))

$(OUTDIR)/test.d$(1)_e$(2)_k$(3)_f$(4)_z$(5)_i$(6).elf: $(POLY_SETUP_DIR)/poly_masking_parameters_d$(1)e$(2)k$(3).o $(OBJS) \
		src/main.c src/poly_masked_sbox.c src/random_bytes.c | prepare_outputs
	@echo "Building configuration d$(1)_e$(2)_k$(3)_f$(4)_z$(5)_i$(6)..."
	$(CC) $(CCFLAGS) $$(CCFLAGS_d$(1)_e$(2)_k$(3)_f$(4)_z$(5)_i$(6)) $(LDFLAGS) \
		-o $$@ $(POLY_SETUP_DIR)/poly_masking_parameters_d$(1)e$(2)k$(3).o $(OBJS) \
		src/random_bytes.c src/poly_masked_sbox.c src/main.c

$(OUTDIR)/test.d$(1)_e$(2)_k$(3)_f$(4)_z$(5)_i$(6).bin: $(OUTDIR)/test.d$(1)_e$(2)_k$(3)_f$(4)_z$(5)_i$(6).elf
	$(OBJCOPY) $$< -O binary $$@
endef

# Define generation of poly_masking_parameters sources
define BUILD_POLY_MASKING_PARAMETERS
$(eval CCFLAGS_d$(1)_e$(2)_k$(3) := -DDEGREE=$(1) -DFAULTS=$(2) -DNUM_SECRETS_PER_ENCODING=$(3) -DPROCESS_ID=$(PROCESS_ID))

$(POLY_SETUP_DIR)/poly_masking_parameters_d$(1)e$(2)k$(3).c: generate_c_variables.sage | prepare_outputs
	sage $$< $(1) $(2) $(3)
	mv src/poly_masking_parameters_d$(1)e$(2)k$(3).c $$@

$(POLY_SETUP_DIR)/poly_masking_parameters_d$(1)e$(2)k$(3).o: $(POLY_SETUP_DIR)/poly_masking_parameters_d$(1)e$(2)k$(3).c
	@echo "Compiling poly_masking_parameters_d$(1)e$(2)k$(3).c..."
	$(CC) $$(CCFLAGS_d$(1)_e$(2)_k$(3)) -c $$< -o $$@
endef


$(foreach d,$(DEGREE_VALUES), \
	$(foreach e,$(FAULTS_VALUES), \
		$(foreach k,$(NUM_SECRETS_PER_ENCODING_VALUES), \
			$(eval $(call BUILD_POLY_MASKING_PARAMETERS,$(d),$(e),$(k))))))

$(foreach d,$(DEGREE_VALUES), \
	$(foreach e,$(FAULTS_VALUES), \
		$(foreach k,$(NUM_SECRETS_PER_ENCODING_VALUES), \
			$(foreach f,$(OPT_FROBENIUS_VALUES), \
				$(foreach z,$(OPT_ZENC_VALUES), \
					$(foreach i,$(NUM_INJECTED_FAULTS_VALUES), \
						$(eval $(call BUILD_SINGLE_CONFIG,$(d),$(e),$(k),$(f),$(z),$(i)))))))))

#############################################
# Unified Build and Run Targets             #
#############################################
.PHONY: all run clean completeclean

all: prepare_outputs \
    $(foreach d,$(DEGREE_VALUES), \
      $(foreach e,$(FAULTS_VALUES), \
      $(foreach k,$(NUM_SECRETS_PER_ENCODING_VALUES), \
      $(foreach f,$(OPT_FROBENIUS_VALUES), \
      $(foreach z,$(OPT_ZENC_VALUES), \
      $(foreach i,$(NUM_INJECTED_FAULTS_VALUES), \
		$(OUTDIR)/test.d$(d)_e$(e)_k$(k)_f$(f)_z$(z)_i$(i).bin))))))

run: prepare_outputs build-config
	@echo "Running configuration $(CONF)…"
	@if [ "$(ARCH)" = "arm-m4" ]; then \
	    qemu-system-arm -cpu cortex-m4 -machine lm3s811evb \
	      -m 192K -nographic -no-reboot -serial mon:stdio \
	      -semihosting -kernel $(OUTDIR)/test.$(CONF).bin; \
	elif [ "$(ARCH)" = "risc-v" ]; then \
	    echo "TODO: run risc-v"; \
	else \
	    echo "Unknown ARCH=$(ARCH)"; exit 1; \
	fi


build-config:
	$(if $(CONF),,\
	  $(error CONF is not set. Usage: make build-config CONF=d1_e2_k1_f0_z1_i3))
	@echo "Building only $(CONF)…"
	@$(MAKE) $(OUTDIR)/test.$(CONF).bin

# Assembly and C object rules
$(OUTDIR)/%.s.o: src/%.s | prepare_outputs
	$(AS) $(ASFLAGS) $^ -o $@

$(OUTDIR)/%.c.o: src/%.c | prepare_outputs
	$(CC) $(CCFLAGS) -DPROCESS_ID=$(PROCESS_ID) -c $< -o $@

#############################################
# Clean Targets                             #
#############################################
clean:
	@echo "Cleaning generated files..."
	@- rm -rf $(OUTDIR)
	@- rm -f poly_masking_parameters_*.c poly_masking_parameters_*.o main_*.o

completeclean:
	@echo "Complete clean: removing all build directories..."
	@- rm -rf build_p*
	@- rm -f src/poly_masking_parameters_*.c src/poly_masking_parameters_*.o src/main_*.o