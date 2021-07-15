#!/bin/sh

qemu-system-x86_64 \
    -m 64 \
    -initrd rootfs.img \
    -kernel bzImage \
    -append 'console=ttyS0 nokaslr panic=1 quiet' \
    --nographic \
    -monitor "/dev/null" \
    -cpu qemu64
