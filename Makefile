.PHONY: xdp
xdp:
	clang -target bpf \
	-D__TARGET_ARCH_arm64 \
	-I/home/xqc/local/openwrt/staging_dir/target-aarch64_cortex-a72_musl/usr/include \
	-I/home/xqc/local/openwrt/staging_dir/toolchain-aarch64_cortex-a72_gcc-13.3.0_musl/include \
	-O2 -Wall -g -c src/xdp.c -o ipv4.o