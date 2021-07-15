gdb-multiarch -q ./pwn2 \
	-ex 'target remote localhost:1234' \
	-ex 'b main' \
	-ex 'b vuln'