.PHONY: all build-linux

BUILD_MODE ?= -buildmode=pie
build-linux: BUILD_FLAGS = $(BUILD_MODE) -ldflags '-s -w'
build-linux:    ## Build the VPC CNI plugin agent using the host's Go toolchain.
	go build $(BUILD_FLAGS) -o bpf-sdk  ./pkg/elfparser

format:       ## Format all Go source code files.
	@command -v goimports >/dev/null || { echo "ERROR: goimports not installed"; exit 1; }
	@exit $(shell find ./* \
	  -type f \
	  -name '*.go' \
	  -print0 | sort -z | xargs -0 -- goimports $(or $(FORMAT_FLAGS),-w) | wc -l | bc)