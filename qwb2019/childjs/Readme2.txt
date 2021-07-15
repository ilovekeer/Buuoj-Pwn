If you want to build it by yourself, plz follow these instructions
```
git clone https://github.com/Microsoft/ChakraCore
cd ChakraCore
git reset --hard 6f09895
patch -p1 < ../diff.patch
cd ChakraCore && ./build.sh
```