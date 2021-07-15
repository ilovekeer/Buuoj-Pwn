from pwn import *
# pay='%15c%8$n'+p64(0x55729cad6197-0x3197+0x53AC+2)
pay='flag{e45edae2-c2af-42a1-9e7c-f28e95655d4d}'
linl=['-','a','b','d','c','f','e','1','2','3','4','5','6','7','8','9','0']
	
for i in range(len(linl)):
	fd=open('./flag1','w+')
	pauu=pay+chr(0x100-ord(linl[i]))
	print linl[i]
	fd.write(pauu)
	fd.close()
	pause()