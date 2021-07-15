#include <stdio.h>
#include <time.h>
#include <malloc.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/time.h>
#include <termio.h>
#include <string.h>

#define high 20
#define wide 30

#define up 1
#define down 2
#define left 3
#define right 4

// void setIO(unsigned int flag) {
//     if(flag)
//         system("stty cbreak -echo");
//     else
//         system("stty cooked echo");
// }

void StringReplace(char *buf, char src, char dest){
    char *p = buf;
    while(*p){
        if(p[0]==src){
            p[0]=dest;
        }
        p++;
    }
}

unsigned int score  = 0;
unsigned int Level = 1;
unsigned int direction = 1;
unsigned int IsEat=0;
unsigned int FoodH=5,FoodW=10;
char Name[0x100];
char flag[0x1000];
unsigned int flag_pos = 0;
char Picture[high][wide];

typedef struct snake{
    unsigned int x;
    unsigned int y;
    struct snake* next;
}Node,*PSnake;

PSnake Init() {
    printf("SnakeMake start!\n");
    unsigned int len=5;
    PSnake head=(PSnake)malloc(sizeof(Node));
    if(head == NULL)
    printf("Snake head make failed!\n");
    head->x=wide/2;
    head->y=high/2+5;
    head->next=NULL;

    unsigned int i=0;
    for(;i<5;i++) {
        PSnake P=(PSnake)malloc(sizeof(Node));
        if(P==NULL) {
            printf("Snake is dead!\n");
            break;
        }
        P->x=wide/2;
        P->y=high/2-i+4;
        P->next=head;
        head=P;
    }
    printf("Snake is alive!\n");
    return head;
}

PSnake Eat(unsigned int x,unsigned int y,PSnake snake) {
    PSnake p=(PSnake)malloc(sizeof(Node));
    if(p==NULL) {
        printf("New head make failed!");
    }
    p->x = x;
    p->y = y;
    p->next=snake;
    score += 1;
    return p;
}

void Walk(unsigned int x,unsigned int y,PSnake snake) {
    PSnake p=snake;
    unsigned int a,b, c=x, d=y;
    while(p!=NULL) {
        a=p->x;
        b=p->y;
        p->x = c;
        p->y = d;
        c=a;
        d=b;
        p=p->next;
    }
}

unsigned int Serch(unsigned int x,unsigned int y,PSnake snake) {
    PSnake q=snake->next;
    while(q!= NULL) {
        if( ( (q->x) == x ) && ( (q->y) == y ) )
        return 1;
        q=q->next;
    }
    return 0;
}

void WriteSnake(PSnake snake) {
    PSnake   p=snake;
    while(p != NULL) {
        Picture[p->y][p->x]=flag[flag_pos%1000];
        p=p->next;
    }
}

void Paint(void) {
    unsigned int y=high,x=wide,i,j;
    for(i=0; i<y; i++)
    for(j=0; j<x; j++)
    Picture[i][j]=' ';
}

static unsigned int cnt=1;
void Print(char* p,unsigned int score,unsigned int Lev) {
    unsigned int a=high,b=wide,i=0,j;
    printf("\033c");
    system("stty -icanon");       // 关缓冲
    system("stty -echo");         // 关回显
    printf("\033[?25l");          // 关闭鼠标显示
    printf("游戏开始!! 移动次数: %d ！\n",cnt);
    cnt++;
    printf("玩家:%s得分:%d\t\t\t\t等级:%d \n",p,score*100,Lev);
    while(i<b*2+2) {
        printf("\033[30;47m \033[0m");
        i++;
    }
    printf("\n");
    for (i=0; i<a; i++) {
        printf("\033[30;47m \033[0m");
        for(j=0; j<b; j++) {
            if(Picture[i][j]!=' '){
                printf("\033[31;42m%c \033[0m",Picture[i][j]);
            }else{
                printf("\033[40m%c \033[0m",Picture[i][j]);
            }
        }
        printf("\033[30;47m \033[0m");
        printf("\n");
    }
    for(i=0;i<=b*2+1;i++) {
        printf("\033[30;47m \033[0m");
    }
    printf("\n");
    if (score < 5){
        printf("\033[30;47m------勤劳的饲养员TaQini正在拿他的加长版flag喂Imagin----------\033[0m\n");
    }else{
        printf("\033[30;47m------Imagin已经吃了%6d分了！300000分还会远么？------------\033[0m\n",score*100);
    }
        printf("\033[30;47m                                                              \033[0m\n");
}

unsigned int MakeFood(void) {
    static unsigned int MC=0;

    while(1) {
        if(MC > ((high * wide)/2 ) )
        return 0;
        srand((int)time(0));
        FoodH=rand()%high;
        FoodW=rand()%wide;
        if(Picture[FoodH][FoodW] == ' ')
        break;
    }

    MC++;
    return 1;
}

PSnake MakeMove(PSnake s) {
    unsigned int x,y;
    PSnake p=s;
    x=s->x,y=s->y;

    if(direction == up)
        y = y - 1;
    if(direction == down)
        y = y + 1;
    if(direction == right)
        x = x + 1;
    if(direction == left)
        x = x - 1;

    if( (y>(high-1)) || ((y<0)) || ((x)<0) || (x>(wide-1)) ) {
        printf("x=%d y=%d s.x=%d s.y=%d \n",x,y,s->x,s->y);
        printf("The snake break the wall!");
        return NULL;
    }

    if(Serch(x,y,s)) {
        printf("x=%d y=%d \n",x,y);
        while(p != NULL) {
            printf("p->x= %d p->y= %d \n",p->x,p->y);
            p=p->next;
        }
        printf("Your snake eat itsself!");
        return NULL;
    }

    if( (x==FoodW) && (y==FoodH) ) {
        s=Eat(x,y,s);
        IsEat=1;
    }

    else {
        Walk(x,y,s);
    }
    return s;
}

unsigned int kbhit(void) {
    struct timeval tv;
    fd_set rdfs;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&rdfs);
    FD_SET(STDIN_FILENO,&rdfs);
    select(STDIN_FILENO+1,&rdfs,NULL,NULL,&tv);
    return FD_ISSET(STDIN_FILENO,&rdfs);
}

void InputCTL(unsigned int level) {
    unsigned int Dir=direction;
    unsigned int timeUse;
    struct timeval start,end;
    gettimeofday(&start,NULL);
    // setIO(1);
    char c,n;
    while(1) {
        gettimeofday(&end,NULL);
        timeUse = 1000000*(end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
        if(timeUse > 1000000 - level*100000)
            break;
        if(kbhit())
            c=getchar();
    }
    // setIO(0);
    if( c == 'w') {
        Dir=1;
    }
    else if( c == 's') {
        Dir=2;
    }
    else if( c == 'a') {
        Dir=3;
    }
    else if( c == 'd') {
        Dir=4;
    }
    else;

    if(!(((Dir == 1) && (direction == down) ) || ((Dir == 2) && (direction == up))
        || ((Dir == 3) && (direction == right)) || ((Dir == 4) && (direction == left)))){
        direction = Dir;
    }
}

unsigned int CheckLevel(unsigned int score) {
    static unsigned int change=0;
    if(((score - change) >= 3) && (Level < 9) ) {
        Level ++;
        change += 3;
    }
    return Level;
}

void printRule(void){
    printf("\033c");
    printf("游戏说明：\n");
    printf("  0.您将操控一条名为Imagin的蛇进行游戏\n");
    printf("  1.每300分升级一次并提速，最高等级为⑨\n");
    printf("  2.不知怎的，挑食的Imagin突然饭量猛增！\n");
    printf("  3.吃够300000分，饲养员TaQini将奖励您shell一个\n\n");
    printf("按键说明：\n");
    printf("  \033[31;47m  a - 左    d - 右  \033[0m\n");
    printf("  \033[31;47m  w - 上    s - 下  \033[0m\n\n");
    printf("获胜条件：\n");
    printf("  \033[31;47m Capture TaQini's flag \033[0m\n");
    printf("  \033[31;47m    拿到TaQini的flag   \033[0m\n");
    printf("途径1：\n");
    printf("  控制Imagin吃豆豆，达到300000分\n");
    printf("途径2：\n");
    printf("  用你善于发现的眼睛，找到游戏中的小bug\n\n");
    // printf("小提示：\n");
    // printf("- 蛇身花纹会根据吃的食物改变哦\n\n");
}

void GiveAwards(){
    system("/bin/sh");    
}

void getName(){
    char buf[0x100];
    printf("请输入玩家昵称(仅限英文)[按回车开始游戏]:");
    scanf("%s",buf);
    strncpy(Name, buf, 0x10);
}

void questionnaire(void){
    int Goal;
    char Answer[0x20];
    puts("你收到了一份来自TaQini的调查问卷");
    printf("1.Snake系列游戏中，贪吃蛇的名字是:");
    scanf("%20s",Answer);
    printf("2.Pwn/Game真好玩儿[Y/n]:");
    scanf("%20s",Answer);
    printf("3.你目标的分数是:");
    scanf("%d",Goal);
}

void GameRun(void) {
    unsigned int GameState=1;
    score=0;
    Level=1;
    printRule();
    getName();
    questionnaire();

    PSnake jack=Init();
    PSnake p=jack;
    
    while(GameState) {
        Paint();
        WriteSnake(jack);

        if(IsEat) {
            if(MakeFood()){
                IsEat=0;
                flag_pos ++;
            }
        }
        // 投食
        Picture[FoodH][FoodW]=flag[(flag_pos+1)%1000];

        Print(Name,score,CheckLevel(score));
        InputCTL(Level);
        jack = MakeMove(jack);

        if( jack == NULL ) {
            GameState=0;
            printf("\033c");
            system("stty icanon");          // 恢复缓冲
            system("stty echo");            // 恢复回显
            printf("\033[?25h");            // 恢复鼠标显示
            printf("Game Over!\n");
        }

        // 奖励shell
        if( score >= 3000 ){
            GameState=0;
            printf("\033c");
            system("stty icanon");          // 恢复缓冲
            system("stty echo");            // 恢复回显
            printf("\033[?25h");            // 恢复鼠标显示
            GiveAwards();
        }
    }
}

unsigned int main(void) {
    setvbuf(stdin,0,1,0);
    setvbuf(stdout,0,2,0);
    // 打开 flag 文件 喂蛇
    unsigned int fd = open("flag",O_RDONLY);
    read(fd,flag,1000);
    StringReplace(flag,'\n','*');
    GameRun();
    return 0;
}
