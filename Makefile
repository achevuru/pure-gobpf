.PHONY: all build-linux

BUILD_MODE ?= -buildmode=pie
build-linux: BUILD_FLAGS = $(BUILD_MODE) -ldflags '-s -w'
build-linux:    ## Build the VPC CNI plugin agent using the host's Go toolchain.
	go build $(BUILD_FLAGS) -o bpf-sdk  ./pkg/elfparser