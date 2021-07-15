#!/bin/sh

qemu-system-x86_64  \
-m 128M \
-cpu kvm64,+smep,+smap \
-kernel ./bzImage \
-initrd rootfs.cpio \
-nographic \
-append "console=ttyS0 nokaslr quiet" \
-gdb  tcp::1234