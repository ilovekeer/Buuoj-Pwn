from pwn import *
from hashlib import sha256
context.log_level='debug'

p=remote("49.4.30.253",31337)
key=p.recvuntil("\n")[:-1]
print key
l=[48,49,50,51,52,53,54,55,56,57]
for i in range(65,91):
    l.append(i)
for i in range(97,123):
    l.append(i)
skr = ""
f = 0
for i in range(len(l)):
    for j in range(len(l)):
        for k in range(len(l)):
            for m in range(len(l)):
                if sha256(key + chr(l[i])+chr(l[j])+chr(l[k])+chr(l[m])).hexdigest().startswith('00000'):
                    print hashlib.sha256(key + chr(l[i])+chr(l[j])+chr(l[k])+chr(l[m])).hexdigest()
                    print key + chr(l[i])+chr(l[j])+chr(l[k])+chr(l[m])
                    skr = chr(l[i])+chr(l[j])+chr(l[k])+chr(l[m])
                    f = 1
                    break
            if f == 1:
                break
        if f == 1:
            break
    if f==1:
        break
p.sendline(skr)
p.interactive()