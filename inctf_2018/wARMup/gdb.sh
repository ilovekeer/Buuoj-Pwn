gdb-multiarch -q ./wARMup \
	-ex 'target remote localhost:1234' \
	-ex 'b *0x10548'