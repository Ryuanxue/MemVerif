#define STACK_OF(type) struct stack_st_##type
struct toy
{
char a;
int b;
char c;
int d;
long e;
char f[16];

};





STACK_OF(void) *sk;

int main()
{
char str[100];
memcpy(str,"uiuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu",99);
//memset(str, 0, 190);
printf("%s\n",str);

printf("%d",sizeof(struct toy));
}
