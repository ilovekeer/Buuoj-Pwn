// g++ pwn.cpp -o pwn -std=c++11 -z now -fpie -pie
#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
using namespace std;
class Attack
{
public:
    Attack()
    {
        new (this)Attack(0,0,"Attack");
    }
    Attack(int damege,int mp,char* skill_name = "Attack"):damage(damege),mp(mp),skill_name(skill_name){}
    ~Attack(){}  
    int GetMP()
    {
        return mp;
    }
    int GetDamage()
    {
        return damage;
    }
    char* GetSkillName()
    {
        return this->skill_name;
    }
private:
    char* skill_name = NULL;
    int damage;
    int mp; 
};

class Thump:public Attack
{
public:
    Thump(int damege,int mp):Attack(damege,mp,"Thump"){}
    ~Thump(){}  
private:
};

class Charm:public Attack
{
public:
    Charm(int damege,int mp):Attack(damege,mp,"Charm"){}
    ~Charm(){}  
private:
};

class Slime
{
public:
    Slime()
    {
        new (this)Slime(20,100,"Slime");
    }
    Slime(int hp,int mp,char* name):hp(hp),mp(mp),name(name)
    {
        attack_list = new vector<Attack*>;
        max_hp = hp;
    }
    virtual void initSkill()
    {
        AddSkill(new Attack(5,0));
    }
    void BeAttack(int a)
    {
        this->hp -= a;
    }
    bool IsDead()
    {
        return this->hp <= 0;
    }
    void AddSkill(Attack *a)
    {
        this->attack_list->push_back(a);
    }
    Attack * ChooseSkill()
    {
        if(this->hp < this->max_hp/2)
        {
            if(this->mp >= 20)
            {
                this->mp -= 20;
                this->hp += max_hp/2;
                cout << "Restore Health\n";
                return NULL;
            }
        }
        int choose = rand()%(this->attack_list->size());
        Attack* a = attack_list->at(choose);
        this->mp -= a->GetMP();
        return a;
    }
    char* GetName(){return this->name;}
    void Info()
    {
        printf("%s:\n",this->name);
        printf("hp : %d/%d\n",this->hp,this->max_hp);
        printf("mp : %d\n",this->mp);
    }
    ~Slime()
    {
        delete(attack_list);
    }
private:
    char* name = NULL;
    int hp;
    int max_hp;
    int mp;
    vector<Attack*> *attack_list;
};

class Goblin:public Slime
{
public:
    Goblin():Slime(30,50,"Goblin"){}
    ~Goblin(){}
    void initSkill()
    {
        AddSkill(new Attack(10,0));
        AddSkill(new Thump(15,5));
    }
private:
};
class Succubus:public Slime
{
public:
    Succubus():Slime(50,200,"Succubus"){}
    ~Succubus(){}
    void initSkill()
    {
        AddSkill(new Attack(10,0));
        AddSkill(new Charm(15,5));
    }
};

class Dragon:public Slime
{
public:
    Dragon():Slime(99999999,99999999,"Dragon"){}
    ~Dragon(){}
    void initSkill()
    {
        AddSkill(new Attack(999,0));
    }
};

class Player
{
private:
    int level = 1;
    int hp = 200;
    int max_hp = 200;
    int mp = 100;
    int max_mp = 100;
    int damage = 20;
    int has_buff = 0;
    int buff_end = 1;
    char* name = NULL;
    int name_len = 0;
public:
    Player(){}
    ~Player(){ free(name);}
    void LevelUp()
    {
        this->level += 1;
        this->max_hp += 2;
        this->max_mp += 2;
        this->hp = max_hp;
        this->mp = max_mp;
        this->damage += 1;
        this->has_buff = 0;
        this->buff_end = 1;
    }
    int ChooseSkill()
    {
        puts("choose your skill:");
        puts("1. Restore Health (+50hp/-20mp)");
        printf("2. Attack (%ddamage/0mp)\n",this->damage);
        puts("3. Use Potion (0damage/30mp)");
        printf("4. Holy Spirit (%ddamage/50mp)\n",this->damage * 2);
        printf("5. Confiteor (%ddamage/80mp)\n",this->damage * 3);
        puts("6. Spirits Within (double the next attack)");
        puts("7. Give up");
        int choose;
        scanf("%d",&choose);
        if(!this->buff_end)
        {
            this->damage /= 2;
            this->buff_end = 1;
        }
        if(this->has_buff)
        {
            this->damage *= 2;
            this->has_buff = 0;
            this->buff_end = 0;
        }
        switch (choose)
        {
        case 1:
            if(this->mp >= 20)
            {
                this->hp += 50;
                this->mp -= 20;
            }
            else
            {
                puts("failed");
            }
            return 0;
        case 2:
            return this->damage;
        case 3:
            this->mp += 30;
            return 0;
        case 4:
            if(this->mp >= 50)
            {
                this->mp -= 50;
                return this->damage * 2;
            }
            else
            {
                puts("failed");
                return 0;
            }
            return 0;
        case 5:
            if(this->mp >= 80)
            {
                this->mp -= 80;
                return this->damage * 3;
            }
            else
            {
                puts("failed");
                return 0;
            }
            return 0;
        case 6:
            this->has_buff = 1;
            return 0;
        default:
            puts("failed");
            return 0;
        }
    }
    bool IsDead()
    {
        return this->hp <= 0;
    }
    void BeAttack(int a)
    {
        this->hp -= a;
    }
    void SetName()
    {
        printf("how long your name:");
        scanf("%d",&name_len);
        this->name = new char[name_len];
        read(0,name,name_len);
    }
    void show()
    {
        printf("name : %s\n",name);
        printf("level : %d\n",level);
    }
    void Info()
    {
        puts("player:");
        printf("hp : %d/%d\n",this->hp,this->max_hp);
        printf("mp : %d/%d\n",this->mp,this->max_mp);
    }

};
list<Player> *scoreborad;
list<char*> *tombstone;

void logo()
{
    cout<<"███╗   ██╗ ██╗   ██╗  ██╗ ██╗     "<<endl;
    cout<<"████╗  ██║ ██║   ██║ ███║ ██║     "<<endl;
    cout<<"██╔██╗ ██║ ██║   ██║ ╚██║ ██║     "<<endl;
    cout<<"██║╚██╗██║ ██║   ██║  ██║ ██║     "<<endl;
    cout<<"██║ ╚████║ ╚██████╔╝  ██║ ███████╗"<<endl;
    cout<<"╚═╝  ╚═══╝  ╚═════╝   ╚═╝ ╚══════╝"<<endl;
}

Player battle(Slime* s,Player p)
{
    int n = 5;
    printf("you meet %s\n",s->GetName());
    s->initSkill();
    while (n--)
    {
        p.Info();
        s->Info();
        int a = p.ChooseSkill();
        s->BeAttack(a);
        if(s->IsDead())
        {
            printf("%s dead,level up!\n",s->GetName());
            p.LevelUp();
            return p;
        }
        printf("the %s ues ",s->GetName());
        auto b = s->ChooseSkill();
        if(b == NULL)
        {
            continue;
        }
        printf("%s\n",b->GetSkillName());
        p.BeAttack(b->GetDamage());
        if(p.IsDead())
        {
            return p;
        }
    }
    printf("%s remember that 2019-nCoV spread everywhere recently, so it back to home\n",s->GetName());
    return p;
}
void show_scoreborad()
{
    for(auto i = scoreborad->begin();i!= scoreborad->end();i++)
    {
        i->show();
    }
}

void game_over()
{
    puts("game over");
    puts("but your courage inspired me");
    puts("leave your name and Praised by future generations");
    printf("name length:");
    int n;
    scanf("%d",&n);
    char* name = new char[n];
    printf("name:");
    read(0,name,n);
    puts("do not give up,may be you can beat it next time!");
    tombstone->push_back(name);
    return;
}

void cleartombstone()
{
    for(auto i = tombstone->begin();i!= tombstone->end();i++)
    {
        delete(*i);
    }
    tombstone->clear();
}

void new_game()
{
    Player p;
    puts("you born in a small village,and learned some swordsmanship from your father\n");
    puts("one day,the dragon destroyed the village,but you were Chopped wood in the forest and escaped\n");
    puts("when you back to the village,you found all your friends ,family and lover killed by the dragon\n");
    puts("you feel sad and angry,decide to avenge their death\n");
    puts("but your power seems too weak to beat the dragon\n");
    puts("so you must pracitce yourself first\n");
    while (1)
    {
        puts("1.practise");
        puts("2.challenge dragon");
        puts("3.give up");
        printf("choose:");
        int n;
        scanf("%d",&n);
        Slime *s = NULL;
        switch (n)
        {
        case 1:
        {
            int choose = rand()%3;
            switch (choose)
            {
            case 0:
                s = new Slime();
                break;
            case 1:
                s = new Goblin();
                break;
            default:
                s = new Succubus();
                break;
            }
            p = battle(s,p);
            delete(s);
            if(p.IsDead())
            {
                game_over();
                return;
            }
            break;
        }
        case 2:
        {
            s = new Dragon();
            p = battle(s,p);
            delete(s);
            if(p.IsDead())
            {
                game_over();
                return;
            }
            puts("you beat it!Congratulations");
            puts("your name will be record in the scoreborad");
            p.SetName();
            scoreborad->push_back(p);
            return;
            break;
        }
        case 3:
        {
            game_over();
            return;
            break;
        }
        default:
            puts("???");
            break;
        }
    }
}

void my_init()
{
    srand(time(NULL));
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
    alarm(80);
    scoreborad = new list<Player>;
    tombstone = new list<char*>;
}

int main()
{
    my_init();
    logo();
    puts("It's boring to stay at home,so i develop Dragon Quest Version -1,hope you engoy it!\n");
    puts("You need to beat the dragon to win the game\n");
    puts("let's start it\n");
    while (1)
    {
        puts("1.new game");
        puts("2.load game(developing)");
        puts("3.scoreboard");
        puts("4.clear scoreboard");
        puts("5.grave sweep");
        puts("6.exit");
        printf("choose:");
        int n;
        scanf("%d",&n);
        switch (n)
        {
        case 1:
            new_game();
            break;
        case 3:
            show_scoreborad();
            break;
        case 4:
            scoreborad->clear();
            break;
        case 5:
            cleartombstone();
            break;
        case 6:
            puts("see you next time");
            free(scoreborad);
            cleartombstone();
            free(tombstone);
            exit(0);
        default:
            puts("???");
            break;
        }
    }
}