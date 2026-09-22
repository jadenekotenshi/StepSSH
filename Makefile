# Host-side build & test (macOS/Linux).  The OPENSTEP build lives in app/Makefile.
# Flags approximate what gcc 2.7.2 will accept: strict C89, no // comments,
# no mixed declarations, no stdint.
CC      ?= cc
CFLAGS  = -std=c89 -pedantic -Wall -Wextra -Wdeclaration-after-statement \
          -Wno-long-long -Wno-unused-parameter -O2 -g
BUILD   = build
SANFLAGS =
# make SAN=1 test   -- build everything with AddressSanitizer + UBSan in build-san/
ifdef SAN
SANFLAGS = -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer
CFLAGS  += $(SANFLAGS)
BUILD   = build-san
endif

CORE_SRC = $(wildcard core/*.c)
TERM_SRC = $(wildcard term/*.c)
TERM_OBJ = $(patsubst term/%.c,$(BUILD)/term_%.o,$(TERM_SRC))
CORE_OBJ = $(patsubst core/%.c,$(BUILD)/%.o,$(CORE_SRC))

all: test

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: core/%.c $(wildcard core/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/term_%.o: term/%.c $(wildcard term/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/test_vt: tests/test_vt.c $(TERM_OBJ)
	$(CC) $(CFLAGS) tests/test_vt.c $(TERM_OBJ) -o $@

$(BUILD)/test_crypto: tests/test_crypto.c tests/vectors.h $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_crypto.c $(CORE_OBJ) -o $@

$(BUILD)/mkkey: tools/mkkey.c $(CORE_OBJ)
	$(CC) -std=gnu99 -Wall -O2 -g $(SANFLAGS) tools/mkkey.c $(CORE_OBJ) -o $@

$(BUILD)/sftpc: tools/sftpc.c $(CORE_OBJ)
	$(CC) -std=gnu99 -Wall -O2 -g $(SANFLAGS) tools/sftpc.c $(CORE_OBJ) -o $@

$(BUILD)/bench: tools/bench.c $(CORE_OBJ)
	$(CC) -std=gnu99 -Wall -O2 $(SANFLAGS) tools/bench.c $(CORE_OBJ) -o $@

bench: $(BUILD)/bench
	$(BUILD)/bench

$(BUILD)/sshc: tools/sshc.c $(CORE_OBJ)
	$(CC) -std=gnu99 -Wall -O2 -g $(SANFLAGS) tools/sshc.c $(CORE_OBJ) -o $@

$(BUILD)/test_bignum: tests/test_bignum.c tests/bn_vectors.h $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_bignum.c $(CORE_OBJ) -o $@

$(BUILD)/test_ecc: tests/test_ecc.c tests/ec_vectors.h $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_ecc.c $(CORE_OBJ) -o $@

$(BUILD)/test_rsa: tests/test_rsa.c tests/rsa_vectors.h $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_rsa.c $(CORE_OBJ) -o $@

$(BUILD)/test_sftp: tests/test_sftp.c $(CORE_OBJ)
	$(CC) $(CFLAGS) tests/test_sftp.c $(CORE_OBJ) -o $@

test: $(BUILD)/test_crypto $(BUILD)/test_vt $(BUILD)/test_sftp $(BUILD)/test_bignum $(BUILD)/test_ecc $(BUILD)/test_rsa
	$(BUILD)/test_crypto
	$(BUILD)/test_vt
	$(BUILD)/test_sftp
	$(BUILD)/test_bignum
	$(BUILD)/test_ecc
	$(BUILD)/test_rsa

interop: $(BUILD)/sshc $(BUILD)/mkkey $(BUILD)/sftpc
	SSHC="$(CURDIR)/$(BUILD)/sshc" sh tests/interop.sh

lint:
	sh tools/lint_openstep.sh

# Syntax-check the Objective-C against the modern SDK (never linked or run).
check-objc:
	for f in app/*.m; do \
	  echo "check $$f"; \
	  $(CC) -fsyntax-only -x objective-c -fno-objc-arc -Wall -Wno-deprecated-declarations \
	    -Wdeclaration-after-statement -Wno-unused-parameter -Icore -Iterm -Iapp $$f || exit 1; \
	done

# Package the sources for transfer into the OPENSTEP VM.
#   dist/SSH.TAR  plain ustar archive (extract with:  tar xf SSH.TAR)
#   dist/SSH.ISO  a CD image containing SSH.TAR (attach it as a CD-ROM in the VM)
DISTFILES = README.md Makefile.openstep core term app tests tools
dist:
	mkdir -p dist
	COPYFILE_DISABLE=1 tar --format ustar --exclude '*.o' --exclude '.DS_Store' \
	    -cf dist/SSH.TAR $(DISTFILES)
	rm -rf dist/iso && mkdir -p dist/iso && cp dist/SSH.TAR dist/iso/
	rm -f dist/SSH.ISO dist/SSH.iso dist/SSH.iso.iso
	# hdiutil picks the extension itself; ISO9660 level 1 keeps 8.3 names OPENSTEP can read
	hdiutil makehybrid -iso -iso-volume-name SSH -o dist/SSH dist/iso >/dev/null
	f=$$(ls dist/SSH.* | grep -iv 'SSH.TAR' | head -1); mv "$$f" dist/SSH.ISO
	rm -rf dist/iso
	@ls -l dist/SSH.TAR dist/SSH.ISO

# Run the UI setup/drawing code on the host (modern AppKit, PostScript calls stubbed).
UI_SRC = app/AppController.m app/ConnectController.m app/KeyGenController.m app/PromptPanel.m \
         app/SFTPBrowser.m app/SSHSession.m app/SecretField.m app/TerminalView.m app/UIHelpers.m \
         app/PortForward.m app/PortForwardController.m
ui-smoke:
	mkdir -p build
	for f in tests/ui_smoke.m $(UI_SRC); do \
	  $(CC) -c -x objective-c -fno-objc-arc -w -g -Icore -Iterm -Iapp $$f -o build/ui_$$(basename $$f .m).o || exit 1; \
	done
	for f in core/*.c term/*.c; do $(CC) -c -w -g -Icore -Iterm $$f -o build/ui_c_$$(basename $$f .c).o || exit 1; done
	$(CC) build/ui_*.o -framework Cocoa -o build/ui_smoke
	build/ui_smoke $${TMPDIR:-/tmp}

session-smoke:
	mkdir -p build
	for f in tests/session_smoke.m $(UI_SRC); do \
	  $(CC) -c -x objective-c -fno-objc-arc -w -g -Icore -Iterm -Iapp $$f -o build/ss_$$(basename $$f .m).o || exit 1; \
	done
	for f in core/*.c term/*.c; do $(CC) -c -w -g -Icore -Iterm $$f -o build/ss_c_$$(basename $$f .c).o || exit 1; done
	$(CC) build/ss_*.o -framework Cocoa -o build/session_smoke
	sh tests/session_smoke.sh

clean:
	rm -rf build build-san

.PHONY: all test interop lint check-objc ui-smoke session-smoke bench dist clean
