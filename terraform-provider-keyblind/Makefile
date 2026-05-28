VERSION ?= 0.1.0
BINARY  := terraform-provider-keyblind
OS      := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH    := $(shell uname -m)

# Normalize arch names for Go
ifeq ($(ARCH),x86_64)
	GOARCH := amd64
else ifeq ($(ARCH),aarch64)
	GOARCH := arm64
else
	GOARCH := $(ARCH)
endif

PLUGIN_DIR := $(HOME)/.terraform.d/plugins/registry.terraform.io/keyblind/keyblind/$(VERSION)/$(OS)_$(GOARCH)

.PHONY: build install test clean

build:
	go build -o $(BINARY) .

install: build
	mkdir -p $(PLUGIN_DIR)
	cp $(BINARY) $(PLUGIN_DIR)/

test:
	go test ./...

clean:
	rm -f $(BINARY)
