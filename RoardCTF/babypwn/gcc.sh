#! /bin/sh
musl-gcc -masm=intel exp.c -static -o exp 
mv exp ./core/exp
cd rootfs
find . | cpio -o --format=newc > ../rootfs.img
cd ..