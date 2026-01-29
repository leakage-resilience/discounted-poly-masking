# Hey Emacs, this is a -*- makefile -*-
#----------------------------------------------------------------------------
#
# Makefile for ChipWhisperer SimpleSerial-AES Program
#
#----------------------------------------------------------------------------
# On command line:
#
# make all = Make software.
#
# make clean = Clean out built project files.
#
# make coff = Convert ELF to AVR COFF.
#
# make extcoff = Convert ELF to AVR Extended COFF.
#
# make program = Download the hex file to the device, using avrdude.
#                Please customize the avrdude settings below first!
#
# make debug = Start either simulavr or avarice as specified for debugging,
#              with avr-gdb or avr-insight as the front end for debugging.
#
# make filename.s = Just compile filename.c into the assembler code only.
#
# make filename.i = Create a preprocessed source file for use in submitting
#                   bug reports to the GCC project.
#
# To rebuild project do "make clean" then "make all".
#----------------------------------------------------------------------------


# Target file name (without extension).
# This is the base name of the compiled .hex file.
TARGET = simpleserial-poly-implementation

# List C source files here.
# Header files (.h) are automatically pulled in.
SRC +=  simpleserial-poly-implementation.c poly_masked_sbox.c random_bytes.c tables.c cycle_counter.c aes-independant.c
MASKING_PARAMETERS_FILE = poly_masking_parameters_d$(DEGREE)e$(FAULTS)k$(SECRETS_PER_ENCODING).c
SRC += $(MASKING_PARAMETERS_FILE)
# Object files to be compiled/linked
# -----------------------------------------------------------------------------

ifeq ($(ENABLE_TRIGGERS),1)
  CFLAGS += -DENABLE_TRIGGERS
endif

ifeq ($(ENABLE_CYCLE_COUNT),1)
  CFLAGS += -DENABLE_CYCLE_COUNT
endif

ifeq ($(ENABLE_FROBENIUS),1)
  CFLAGS += -DENABLE_FROBENIUS
endif

ifeq ($(DISABLE_RANDOMNESS),1)
  CFLAGS += -DDISABLE_RANDOMNESS
endif

CFLAGS += $(EXTRA_OPTS) #-DTINYAES128C
# Debugging: Print the final CFLAGS
$(info CFLAGS: $(CFLAGS))


#EXTRA_OPTS = NO_EXTRA_OPTS
#CFLAGS += -O2 -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16 -Wall
#ASFLAGS = -mcpu=cortex-m4 -mthumb -O2 -mfloat-abi=hard -mfpu=fpv4-sp-d16

ifeq ($(CRYPTO_TARGET),)
  ${info No CRYPTO_TARGET passed - defaulting to TINYAES128C}
  CRYPTO_TARGET = TINYAES128C
endif

${info Building for platform ${PLATFORM} with CRYPTO_TARGET=$(CRYPTO_TARGET)}

#Add simpleserial project to build
include ../simpleserial/Makefile.simpleserial

FIRMWAREPATH = ../.
include $(FIRMWAREPATH)/Makefile.inc





