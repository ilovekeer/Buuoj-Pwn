#!/bin/bash
qemu-system-x86_64 -kernel ./4.20.0-bzImage -initrd  ./rootfs.img -append 'console=ttyS0 root=/dev/sda quiet' -m 128M --nographic #-monitor /dev/null

