gdb-multiarch -q ./root_me_stack_buffer_overflow_basic \
	-ex 'target remote localhost:1234' \
	-ex 'b main' \
	-ex 'b *0x000104FC'