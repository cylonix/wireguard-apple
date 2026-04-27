# SPDX-License-Identifier: MIT
#
# Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

# These are generally passed to us by xcode, but we set working defaults for standalone compilation too.
ARCHS ?= x86_64 arm64
PLATFORM_NAME ?= macosx
SDKROOT ?= $(shell xcrun --sdk $(PLATFORM_NAME) --show-sdk-path)
CONFIGURATION_BUILD_DIR ?= $(CURDIR)/out
CONFIGURATION_TEMP_DIR ?= $(CURDIR)/.tmp

export PATH := $(PATH):/usr/local/bin:/opt/homebrew/bin
export CC ?= clang
LIPO ?= lipo
DESTDIR ?= $(CONFIGURATION_BUILD_DIR)
BUILDDIR ?= $(CONFIGURATION_TEMP_DIR)/wireguard-go-bridge

CFLAGS_PREFIX := $(if $(DEPLOYMENT_TARGET_CLANG_FLAG_NAME),-$(DEPLOYMENT_TARGET_CLANG_FLAG_NAME)=$($(DEPLOYMENT_TARGET_CLANG_ENV_NAME)),) -isysroot $(SDKROOT) -arch
GOARCH_arm64 := arm64
GOARCH_x86_64 := amd64
GOOS_macosx := darwin
GOOS_iphoneos := ios

build: $(DESTDIR)/libwg-go.a
version-header: $(DESTDIR)/wireguard-go-version.h

# __BEGIN_CYLONIX_MOD__
# Prefer the tailscale-pinned Go toolchain (cached by tool/gocross-wrapper.sh
# at ~/.cache/tsgo/<rev>/) when the sibling tailscale checkout pins one.
# Cylonix's v1.96.4-rebased tailscale fork requires go >= 1.26.1, which is
# newer than what /usr/local/go ships on most dev machines; without this
# override the Xcode wireguard-go-bridge build copies /usr/local/go (1.25.x)
# into a tmp goroot and then fails with "module ../../../tailscale requires
# go >= 1.26.1". When the tsgo cache is absent we fall back to upstream's
# behaviour and rely on /usr/local/go.
TAILSCALE_TSGO_REV := $(strip $(shell cat $(CURDIR)/../../../tailscale/go.toolchain.rev 2>/dev/null))
ifneq ($(TAILSCALE_TSGO_REV),)
TAILSCALE_TSGO := $(HOME)/.cache/tsgo/$(TAILSCALE_TSGO_REV)
ifeq ($(wildcard $(TAILSCALE_TSGO)/bin/go),$(TAILSCALE_TSGO)/bin/go)
REAL_GOROOT := $(TAILSCALE_TSGO)
PATH := $(TAILSCALE_TSGO)/bin:$(PATH)
endif
endif

ifeq ($(REAL_GOROOT),)
REAL_GOROOT := $(shell go env GOROOT 2>/dev/null)
endif
# Xcode does not pass user shell $PATH setting.
ifeq ($(REAL_GOROOT),)
	REAL_GOROOT=/usr/local/go
	REAL_GOROOT_HARD_SET=yes
	PATH += :/usr/local/go/bin
endif
# __END_CYLONIX_MOD__
export GOROOT := $(BUILDDIR)/goroot
# __BEGIN_CYLONIX_MOD__
# Track REAL_GOROOT in a stamp file so a switch between /usr/local/go and the
# tsgo cache (or any GOROOT change) invalidates the prepared GOROOT. Without
# this, an Xcode build that rsync'd from /usr/local/go (1.25.x) survives a
# Makefile change pointing PATH at tsgo (1.26.x), and `go build` fails with
# "compile: version go1.25.x does not match go tool version go1.26.x".
$(BUILDDIR)/.real_goroot.stamp: FORCE
	@mkdir -p "$(BUILDDIR)"
	@printf '%s\n' "$(REAL_GOROOT)" > "$@.new"
	@if ! cmp -s "$@.new" "$@" 2>/dev/null; then mv "$@.new" "$@"; else rm "$@.new"; fi
.PHONY: FORCE
FORCE:

$(GOROOT)/.prepared: $(BUILDDIR)/.real_goroot.stamp
# __END_CYLONIX_MOD__
	@echo "PATH=${PATH}"
	@echo "REAL_GOROOT=${REAL_GOROOT} REAL_GOROOT_HARD_SET=${REAL_GOROOT_HARD_SET}"
	[ -n "$(REAL_GOROOT)" ]
	mkdir -p "$(GOROOT)" "$(BUILDDIR)"
	rsync -a --delete --exclude=pkg/obj/go-build "$(REAL_GOROOT)/" "$(GOROOT)/"
	chmod -R u+w "$(GOROOT)"
	TMPDIR="$(BUILDDIR)" cat goruntime-*.diff | TMPDIR="$(BUILDDIR)" patch -p1 -f -N -r- -d "$(GOROOT)"
	touch "$@"

define libwg-go-a
$(BUILDDIR)/libwg-go-$(1).a: export CGO_ENABLED := 1
$(BUILDDIR)/libwg-go-$(1).a: export CGO_CFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libwg-go-$(1).a: export CGO_LDFLAGS := $(CFLAGS_PREFIX) $(ARCH)
$(BUILDDIR)/libwg-go-$(1).a: export GOOS := $(GOOS_$(PLATFORM_NAME))
$(BUILDDIR)/libwg-go-$(1).a: export GOARCH := $(GOARCH_$(1))
$(BUILDDIR)/libwg-go-$(1).a: $(GOROOT)/.prepared go.mod
	go build -gcflags '-N' -trimpath -v -o "$(BUILDDIR)/libwg-go-$(1).a" -buildmode c-archive -tags ts_macext
	echo "build ligwg-go at $(BUILDDIR)"
	rm -f "$(BUILDDIR)/libwg-go-$(1).h"
endef
$(foreach ARCH,$(ARCHS),$(eval $(call libwg-go-a,$(ARCH))))

$(DESTDIR)/wireguard-go-version.h: go.mod $(GOROOT)/.prepared
	@mkdir -p "$(DESTDIR)"
	 sed -E -n 's/.*golang\.zx2c4\.com\/wireguard +v[0-9.]+-[0-9]+-([0-9a-f]{8})[0-9a-f]{4}.*/#define WIREGUARD_GO_VERSION "\1"/p' "$<" > "$@"

$(DESTDIR)/libwg-go.a: $(foreach ARCH,$(ARCHS),$(BUILDDIR)/libwg-go-$(ARCH).a)
	@mkdir -vp "$(DESTDIR)"
	$(LIPO) -create -output "$@" $^

clean:
	rm -rf "$(BUILDDIR)" "$(DESTDIR)/libwg-go.a" "$(DESTDIR)/wireguard-go-version.h"

install: build

.PHONY: clean build version-header install
