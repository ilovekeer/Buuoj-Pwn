#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
 
int main(int argc, char *argv[])
{
    int fd = open("/dev/stdout", O_WRONLY);
 
    if (argc == 2 && strcmp(argv[1], "fclose") == 0) {
        fclose(stdout);
    } else {
        close(1);
    }
 
    dup(fd);
 
    stdout = fdopen(fd,"w");
 
    printf("haha\n");
 
    return 0;
}