gdb \
	-ex "add-auto-load-safe-path $(pwd)" \
	-ex "file vmlinux" \
	-ex 'set arch i386:x86-64:intel' \
	-ex 'target remote localhost:1234' \
	-ex 'disconnect' \
	-ex 'set arch i386:x86-64' \
	-ex 'target remote localhost:1234' \
	-ex 'add-symbol-file ./core/test1.ko 0xffffffffc0000000' \
	-ex 'b test1_write'