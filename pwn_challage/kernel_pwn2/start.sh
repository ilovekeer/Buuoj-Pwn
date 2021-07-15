#!/bin/sh

qemu-system-x86_64  \
-m 256M \
-cpu kvm64,+smap,+smep \
-kernel ./bzImage \
-initrd rootfs.img \
-nographic \
-append "console=ttyS0 kaslr quiet" \
-gdb tcp::1234 