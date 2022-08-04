all: run

run: build_ebpf 
	cargo build
	cargo xtask run -r sudo

bootstrap:
	rustup install nightly
	cargo install bpf-linker

build_ebpf:
	cargo xtask build-ebpf


.PHONY: all build_ebpf bootstrap
