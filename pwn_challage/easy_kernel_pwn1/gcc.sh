#! /bin/sh
gcc -masm=intel exp.c -static -o exp 
mv exp ./core/exp
cd core
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..