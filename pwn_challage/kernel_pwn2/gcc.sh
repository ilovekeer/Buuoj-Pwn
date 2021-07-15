#! /bin/sh
musl-gcc -pthread -masm=intel exp.c -static -o exp 
mv exp ./core/exp
cd core
find . | cpio -o --format=newc > ../rootfs.img
cd ..