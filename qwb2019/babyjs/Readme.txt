This is a vulnerable software. I patched some of the vulnerabilities, but I think you can still find a way to exploit it, right? Prove it.

If you want to build the chall by yourself, plz type the following commands
```
git clone https://github.com/cesanta/mjs
cd mjs
git reset --hard fd0bf16
patch -p1 < ../diff.patch
cd mjs && make
```
