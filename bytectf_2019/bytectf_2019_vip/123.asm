A = sys_number
A == openat ? ok:allow

ok:
return ERRNO(0)
allow:
return ALLOW