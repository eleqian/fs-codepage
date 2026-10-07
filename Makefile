#---------------------------------------------------------------------------------
# fs-codepage -- root makefile (sysmodule only, no overlay)
#---------------------------------------------------------------------------------
MAKEFILES	:=	sysmod
TARGETS		:= $(foreach dir,$(MAKEFILES),$(CURDIR)/$(dir))

.PHONY: all clean dist $(TARGETS)

all: $(TARGETS)
	@mkdir -p out/
	@cp -R sysmod/out/* out/
	# Mirror contents/ wholesale instead of merging: a TID change would otherwise
	# leave the previous contents/<tid>/ behind, shipping two sysmodule directories.
	@rm -rf out/atmosphere/contents
	@cp -R sysmod/out/atmosphere/contents out/atmosphere/contents

$(TARGETS):
	@$(MAKE) -C $@

clean:
	@rm -rf out
	@rm -f fs-codepage-sysmodule.zip
	@for i in $(TARGETS); do $(MAKE) -C $$i clean || exit 1; done;

dist: all
	@echo making dist ...
	@python -m zipfile -c fs-codepage-sysmodule.zip out/
