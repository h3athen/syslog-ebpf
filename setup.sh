#!/bin/bash

# build ebpf
	cargo xtask build-ebpf
# build userspace
	cargo build
# run
	cargo xtask run
