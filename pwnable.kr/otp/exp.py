from pwn import *
import subprocess

io = process(["./otp", ""], stderr = subprocess.STDOUT)
io.interactive()