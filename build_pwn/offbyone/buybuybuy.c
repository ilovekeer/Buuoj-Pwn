#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct commodity{//9+4+4+4+4=25=0x19
	int name_size;
	char *name;
	int des_size;
	char *desrcript;	
}Comm;

//global var
//aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
//int 100;
char yourname[32];
Comm* commod[20];
int len ;
Comm *a;


int readint(){
	int i;
	if(!scanf("%d",&i))
		return 0;
	printf("You input:%d\n\n",i);
	fflush(stdin);
	fflush(stdout);
	return i;
}

void readstr(char *arr,int len){
	char temp[25];
	sprintf(temp,"%%%ds",len);
	scanf(temp,arr);
	printf("You input:%s\n\n",arr);
	fflush(stdin);
	fflush(stdout);
}

void init(){
	setbuf(stdin,0);
	setbuf(stdout,0);
	setbuf(stderr,0);
	puts("As for a bran-new robot(i am not just a computer repeater.),");
	puts("I only admire the MaYun Daddy among you(people)");
	puts("So today just buy~buy~buy~");
	putchar(10);
	//100 = 100;
	//a = malloc(sizeof(Comm));


	len = 0;
	memset(yourname,0,32);
	// commod[0] = malloc(sizeof(Comm));
	// memset(commod[0],0,sizeof(Comm));
	// for(int i=1;i<20;i++){
	// 	commod[i] = malloc(sizeof(Comm));
	// 	memset(commod[i],0,sizeof(Comm));
	// }
	//printf("the commod address is %p\n\n\n\n",commod);
	//printf("the yourname address is %p\n\n\n\n",yourname);
	//free(a);
}
int inputYourName(){
	puts("What's your name?");
	printf("Enter your name(1~32):");
	readstr(yourname,32);
	if(yourname==NULL)
		return 1;
	return 0;
}


void menu(){
	puts("1. Add to shopping cart");
	puts("2. Modify product information");
	puts("3. Display all products");
	puts("4. Buy shopping cart");
	puts("5. Empty shopping cart");
	puts("6. Change your name.");
	puts("7. exit");
	printf("Your choice:");
}



void add(){
	puts("\nadd~add~add~\n");

	printf("the quantity of commodity is %d.\n",len);

	if(len > 100 || len == 100){
		puts("Your shopping cart is full.");
		puts("You can empty shopping cart or just look it.");
		puts("Add fail!\n");
		return;
	}

	puts("please tell me the desrcription's size.");
	int des_size = readint();
	if(des_size<1){
		puts("Maybe you are a god,but i donnot like you.");
		puts("Add fail!");
		return;
	}
	puts("please tell me the desrcript of commodity.");
	char *desrcript = malloc(sizeof(char)*des_size);
	if(desrcript == NULL){
		puts("Maybe there is something wrong inside of me.");
		puts("Please try it again.");
		return;
	}
	readstr(desrcript,des_size);


	puts("What do you want to buy?");
	//puts("please tell me the commodity-name's size(0~20).");
	puts("please tell me the commodity-name's size.");
	int name_size = readint();
	// if(name_size<1 || name_size>20){
	// 	puts("Maybe you are a god,but i donnot like you.");
	// 	puts("Add fail!\n");
	// 	return;
	// }
	puts("please tell me the commodity-name.");
	char *name = malloc(sizeof(char)*name_size);

	//printf("the malloc address is %p\n\n\n\n",name);

	if(name == NULL){
		puts("Maybe there is something wrong inside of me.");
		puts("Please try it again.");
		puts("Add fail!\n");
		return;
	}
	readstr(name,name_size);
	
	
	

	//len+=1;
	//(*commod[len]).name_size = malloc(sizeof(int));
	
	//(*commod[len]).des_size = malloc(sizeof(int));
	a = malloc(sizeof(Comm));
	memset(a,0,sizeof(Comm));

	// printf("a's addr is %p\n",&a);
	// printf("a's addr is %p\n",a);
	// printf("a's addr is %p\n",&(*a).name_size);

	(*a).name_size = name_size;
	(*a).desrcript = desrcript;
	(*a).name = name;
	(*a).des_size = des_size;
	commod[len] = a;

	// printf("The No.%d commodity :\n",len);
	// printf("commodity's size is %p\n",&(*commod[len]).name_size);
	// printf("commodity's name is %p\n",&(*commod[len]).name);
	// printf("commodity's des_size is %p\n",&(*commod[len]).des_size);
	// printf("commodity's des is %p\n",&(*commod[len]).desrcript);


	len += 1;

    printf("the quantity of commodity is %d.\n",len);
	puts("Add done!\n");
}
void modify(){
	puts("\nmodify~modify~modify~\n");

	printf("the quantity of commodity is %d.\n",len);

	puts("Please input the index of the commodity");
	printf("The index is ");
	int i = readint();
	if(i<len && i>-1){
		printf("commodity's size is %d\n",(*commod[i]).name_size);
		printf("commodity's name is %s\n",(*commod[i]).name);
		printf("commodity's des_size is %d\n",(*commod[i]).des_size);
		printf("commodity's des is %s\n",(*commod[i]).desrcript);
		putchar(10);
		
		
		// puts("please tell me the commodity-name's size(0~20).");
		// int name_size = readint();
		// if(name_size<1 || name_size>20){
		// 	puts("Maybe you are a god,but i donnot like you.");
		// 	puts("Modify fail!\n");
		// 	return;
		// }
		puts("please tell me the new commodity's name.");
		//char *name = malloc(sizeof(char)*name_size);
		// if(name == NULL){
		// 	puts("Maybe there is something wrong inside of me.");
		// 	puts("Please try it again.");
		// 	return;
		// }
		// char *p = (*commod[i]).name;
		// for(int j=0; ;j++){
		// 	if(read(0,p,1)!=1)
		// 		break;
		// 	p++;
		// }
		read(0,(*commod[i]).name,(*commod[i]).name_size);
		
		puts("please tell me the new commodity's desrcription.");
		// char *y = (*commod[i]).desrcript;
		// for(int j=0; ;j++){
		// 	if(read(0,y,1)!=1)
		// 		break;
		// 	y++;
		// }
		read(0,(*commod[i]).desrcript,(*commod[i]).des_size);
		
		//commod[i].name_size = name_size;
		//commod[i].name = name;	
		puts("Modify done!\n");
	}else{
		puts("go away!");
		puts("Modify fail!\n");
		return;
	}
	return ;
}

void buy(){
	puts("\nbuy~buy~buy~\n");
	if(len == 0){
		puts("Your are a poor man.");
		puts("Buy fail\n");
		return;
	}
	printf("%s's shopping cart:\n",yourname);
	printf("the quantity of commodity is %d.\n",len);

	for(int i=0;i<len;i++){		
		printf("The No.%d commodity :\n",i);
		printf("commodity's size is %d\n",(*commod[i]).name_size);
		printf("commodity's name is %s\n",(*commod[i]).name);
		printf("commodity's des_size is %d\n",(*commod[i]).des_size);
		printf("commodity's des is %s\n",(*commod[i]).desrcript);
		putchar(10);
		(*commod[i]).name_size = 0;
		free((*commod[i]).name);			
	}
	len = 0;
	puts("Buy done!\n");
}

void display(){
	puts("\ndisplay~display~display~\n");
	if(len == 0){
		puts("Your are a poor man.Nothing in shopping cart.");
		puts("Display fail!\n");
		return;
	}
	puts("Do you want to display all commodity?");
	puts("1. all");
	puts("2. just one");
	printf("Your choice:");
	
	
	int i =	readint();
	int index = 0;
	switch(i){
		case 1:
			printf("%s's shopping cart:\n",yourname);
			printf("the quantity of commodity is %d.\n",len);
			for (int i = 0; i<len; ++i){
				printf("des address is %p.\n",(*commod[i]).desrcript);
				printf("name address is %p.\n",(*commod[i]).name);

				printf("The No.%d commodity :\n",i);
				printf("commodity's size is %d\n",(*commod[i]).name_size);
				printf("commodity's name is %s\n",(*commod[i]).name);
				printf("commodity's des_size is %d\n",(*commod[i]).des_size);
				printf("commodity's des is %s\n",(*commod[i]).desrcript);

			
				putchar(10);
			}
			puts("Display done!\n");
			break;
		case 2:
			printf("the quantity of commodity is %d.\n",len);
			puts("Please input the index of the commodity");
			printf("The index is ");
			index =	readint();	
			if(index < len && index > -1){
				printf("The No.%d commodity :\n",index);
				printf("commodity's size is %d\n",(*commod[i]).name_size);
				printf("commodity's name is %s\n",(*commod[i]).name);
				printf("commodity's des_size is %d\n",(*commod[i]).des_size);
				printf("commodity's des is %s\n",(*commod[i]).desrcript);
				puts("Display done!\n");
			}else{
				puts("go away!");
				puts("Display fail!\n");
				return;
			}
			break;
	}
	return;
}

void empty(){
	puts("\nempty~empty~empty~\n");
	if(len == 0){
		puts("Your are a poor man.Nothing in shopping cart.");
		puts("Empty fail!\n");
		return;
	}
	puts("Do you want to empty all commodity?");
	puts("1. all");
	puts("2. just one");
	printf("Your choice:");

	int i =	readint();


	int index = 0;
	switch(i){
		case 1:
			printf("%s's shopping cart:\n",yourname);
			printf("the quantity of commodity is %d.\n",len);
			for (int i = 0; i<100; ++i){
				// printf("The No.%d commodity :\n",i);
				// printf("commodity's size is %d\n",(*commod[i]).name_size);
				// printf("commodity's name is %s\n",(*commod[i]).name);
				// printf("commodity's des_size is %d\n",(*commod[i]).des_size);
				// printf("commodity's des is %s\n",(*commod[i]).desrcript);
				// putchar(10);
				(*commod[i]).name_size = 0;
				(*commod[i]).des_size = 0;
				free((*commod[i]).name);
				free((*commod[i]).desrcript);
				(*commod[i]).name = NULL;
				(*commod[i]).desrcript = NULL;			
			}
			len = 0;
			puts("Empty done!\n");
			break;
		case 2:
			printf("the quantity of commodity is %d.\n",len);

			puts("Please input the index of the commodity");
			printf("The index is ");
			index =	readint();	
			//printf("this si %d.\n",(*commod[index]).name_size);
			if(index<len && index>-1){
				// printf("The No.%d commodity :\n",index);
				// printf("commodity's size is %d\n",(*commod[i]).name_size);
				// printf("commodity's name is %s\n",(*commod[i]).name);
				// printf("commodity's des_size is %d\n",(*commod[i]).des_size);
				// printf("commodity's des is %s\n",(*commod[i]).desrcript);
				puts("Empty done!\n");
				(*commod[index]).name_size = 0;
				free((*commod[index]).name);
				len -= 1;
				printf("the quantity of commodity is %d.\n\n",len);
				
				//len -= 1;//0x6030d0
				for(i=index;i<len;i++){
					(*commod[i]).name_size = (*commod[i+1]).name_size;
					(*commod[i]).name = (*commod[i+1]).name;
					(*commod[i]).des_size = (*commod[i+1]).des_size;
					(*commod[i]).desrcript = (*commod[i+1]).desrcript;
				}
			}else{
				puts("go away!");
				puts("Empty fail!\n");
				return;
			}
			break;
	}
	return;
}

void changeYourName(){
	printf("Your name is %s.\n",yourname);
	printf("Change your name(1~32):");
	readstr(yourname,32);
}

int main(void){

	init();
	if(inputYourName()){
		puts("fail to get your name.");
		puts("Goodbye.");
		return 0;
	}

	//printf("the malloc address is %p\n\n\n\n",commod);
	//printf("the malloc address is %p\n\n\n\n",yourname);

	while(1){
		menu();
		int i =	readint();
		if(i==0){
			puts("get too much zero.");
			return 0;
		}
		switch(i){
			case 1:
				add();
				//printf("the commod is %s\n\n\n\n",commod);
				//printf("the yourname is %s\n\n\n\n",yourname);
				break;
			case 2:
				modify();
				break;
			case 3:
				display();
				break;
			case 4:
				buy();
				break;
			case 5:
				empty();
				break;
			case 6:
				changeYourName();
				break;
			case 7:
				puts("Loser,the poor man.");
				exit(0);
			default:
				puts("Please input the num in 1~6,No trick.\n");
				break;
		}
	}

	return 0;
}