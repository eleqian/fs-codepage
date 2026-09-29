#---------------------------------------------------------------------------------
# fs-codepage -- root makefile (sysmodule only, no overlay)
#---------------------------------------------------------------------------------
MAKEFILES	:=	sysmod
TARGETS		:= $(foreach dir,$(MAKEFILES),$(CURDIR)/$(dir))

.PHONY: all clean dist $(TARGETS)

all: $(TARGETS)
	@mkdir -p out/
	@cp -R sysmod/out/* out/

$(TARGETS):
	@$(MAKE) -C $@

clean:
	@rm -rf out
	@rm -f fs-codepage-sysmodule.zip
	@for i in $(TARGETS); do $(MAKE) -C $$i clean || exit 1; done;

dist: all
	@echo making dist ...
	@python -m zipfile -c fs-codepage-sysmodule.zip out/
