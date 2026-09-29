#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitpro")
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libnx/switch_rules

#---------------------------------------------------------------------------------
# fs-codepage -- standalone fs codepage (UTF-8) patch module.
# Extracted from the sys-patch fork; builds by itself so it can coexist with
# the ORIGINAL upstream sys-patch (title id 420000000000000B).
#---------------------------------------------------------------------------------
TARGET		:=	fs-codepage
BUILD		:=	build
SOURCES		:=	src ../common/minIni
DATA		:=	data
INCLUDES	:=	include ../common

#---------------------------------------------------------------------------------
# options for code generation
#---------------------------------------------------------------------------------
ARCH	:=	-march=armv8-a+crc+crypto -mtune=cortex-a57 -mtp=soft -fPIE

CFLAGS	:=	-g -Wall -O2 -ffunction-sections \
			$(ARCH) $(DEFINES) $(CUSTOM_DEFINES)

CFLAGS	+=	$(INCLUDE) -D__SWITCH__

CXXFLAGS	:= $(CFLAGS) -std=c++23 -fno-rtti -fno-exceptions
CXXFLAGS += $(EXTRA_FLAGS)
# -fno-toplevel-reorder: keep top-level asm (fs patch function _end labels) in
# source order, otherwise GCC emits them before the deferred function bodies
# and patch_code_size() would compute 0. See tools/check_patch_sizes.py.
CXXFLAGS	+=	-fno-toplevel-reorder

ASFLAGS	:=	-g $(ARCH)
LDFLAGS	=	-specs=$(DEVKITPRO)/libnx/switch.specs -g $(ARCH) -Wl,-Map,$(notdir $*.map)

LIBS	:= -lnx

#---------------------------------------------------------------------------------
# list of directories containing libraries, this must be the top level containing
# include and lib
#---------------------------------------------------------------------------------
LIBDIRS	:= $(PORTLIBS) $(LIBNX)


#---------------------------------------------------------------------------------
# no real need to edit anything past this point unless you need to add additional
# rules for different file extensions
#---------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#---------------------------------------------------------------------------------

export OUTPUT	:=	$(CURDIR)/$(TARGET)
export TOPDIR	:=	$(CURDIR)

export VPATH	:=	$(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
			$(foreach dir,$(DATA),$(CURDIR)/$(dir))

export DEPSDIR	:=	$(CURDIR)/$(BUILD)

CFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c)))
CPPFILES	:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
SFILES		:=	$(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
BINFILES	:=	$(foreach dir,$(DATA),$(notdir $(wildcard $(dir)/*.*)))

#---------------------------------------------------------------------------------
# use CXX for linking C++ projects, CC for standard C
#---------------------------------------------------------------------------------
ifeq ($(strip $(CPPFILES)),)
#---------------------------------------------------------------------------------
	export LD	:=	$(CC)
#---------------------------------------------------------------------------------
else
#---------------------------------------------------------------------------------
	export LD	:=	$(CXX)
#---------------------------------------------------------------------------------
endif
#---------------------------------------------------------------------------------

export OFILES_BIN	:=	$(addsuffix .o,$(BINFILES))
export OFILES_SRC	:=	$(CPPFILES:.cpp=.o) $(CFILES:.c=.o) $(SFILES:.s=.o)
export OFILES 	:=	$(OFILES_BIN) $(OFILES_SRC)
export HFILES_BIN	:=	$(addsuffix .h,$(subst .,_,$(BINFILES)))

export INCLUDE	:=	$(foreach dir,$(INCLUDES),-I$(CURDIR)/$(dir)) \
			$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
			-I$(CURDIR)/$(BUILD)

export LIBPATHS	:=	$(foreach dir,$(LIBDIRS),-L$(dir)/lib)

ifeq ($(strip $(CONFIG_JSON)),)
	jsons := $(wildcard *.json)
	ifneq (,$(findstring $(TARGET).json,$(jsons)))
		export APP_JSON := $(TOPDIR)/$(TARGET).json
	else
		ifneq (,$(findstring config.json,$(jsons)))
			export APP_JSON := $(TOPDIR)/config.json
		endif
	endif
else
	export APP_JSON := $(TOPDIR)/$(CONFIG_JSON)
endif

#---------------------------------------------------------------------------------
# install layout: atmosphere/contents/<TID>/{exefs.nsp,toolbox.json,flags/boot2.flag}
#---------------------------------------------------------------------------------
TITLE_ID := 42000000000000E0

#---------------------------------------------------------------------------------
# python (用于构建守卫与 dist 打包；msys2 无 zip 命令)
#---------------------------------------------------------------------------------
PATCHCHECK_PY := $(shell command -v python3 2>/dev/null || command -v python 2>/dev/null)

.PHONY: $(BUILD) clean all

#---------------------------------------------------------------------------------
all: $(BUILD)

$(BUILD):
	@[ -d $@ ] || mkdir -p $@
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(CURDIR)/Makefile
	@if [ -n "$(PATCHCHECK_PY)" ]; then $(MAKE) --no-print-directory check-patch-sizes || exit 1; else echo "warning: python not found, skipping patch size check"; fi

	@rm -rf out/
	@mkdir -p out/atmosphere/contents/$(TITLE_ID)/flags
	@touch out/atmosphere/contents/$(TITLE_ID)/flags/boot2.flag
	@cp $(CURDIR)/toolbox.json out/atmosphere/contents/$(TITLE_ID)/toolbox.json
	@cp $(CURDIR)/$(TARGET).nsp out/atmosphere/contents/$(TITLE_ID)/exefs.nsp

#---------------------------------------------------------------------------------
clean:
	@echo clean ...
ifeq ($(strip $(APP_JSON)),)
	@rm -fr $(BUILD) $(TARGET).nro $(TARGET).nacp $(TARGET).elf
else
	@rm -fr $(BUILD) $(TARGET).nsp $(TARGET).nso $(TARGET).npdm $(TARGET).elf
endif
	@rm -rf out/
	@rm -f fs-codepage-sysmodule.zip

#---------------------------------------------------------------------------------
dist: all
	@echo making dist ...

	@rm -f fs-codepage-sysmodule.zip
	@cd out && $(PATCHCHECK_PY) -m zipfile -c ../fs-codepage-sysmodule.zip .

#---------------------------------------------------------------------------------
# build-time guard: verify every fs codepage patch function's runtime size
# (end-label delta) equals its ELF symbol size and fits the hole at its patch
# site in the fs binary. Same guard as the sys-patch build; kept in sync with
# tools/check_patch_sizes.py.
#---------------------------------------------------------------------------------

.PHONY: check-patch-sizes
check-patch-sizes:
ifdef PATCHCHECK_PY
	@$(PATCHCHECK_PY) tools/check_patch_sizes.py $(CURDIR)/$(TARGET).elf --main $(CURDIR)/src/fs_codepage.cpp
else
	@echo "warning: python not found, skipping patch size check"
endif
#---------------------------------------------------------------------------------
else
.PHONY:	all

DEPENDS	:=	$(OFILES:.o=.d)

#---------------------------------------------------------------------------------
# main targets
#---------------------------------------------------------------------------------
ifeq ($(strip $(APP_JSON)),)

all	:	$(OUTPUT).nro

else

all	:	$(OUTPUT).nsp

$(OUTPUT).nsp	:	$(OUTPUT).nso $(OUTPUT).npdm

$(OUTPUT).nso	:	$(OUTPUT).elf

endif

$(OUTPUT).elf	:	$(OFILES)

$(OFILES_SRC)	: $(HFILES_BIN)

%.bin.o	%_bin.h :	%.bin
	@echo $(notdir $<)
	@$(bin2o)

-include $(DEPENDS)

endif
#---------------------------------------------------------------------------------
