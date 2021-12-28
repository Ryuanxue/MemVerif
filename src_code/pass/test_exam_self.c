
#include <string.h>
#include <stdio.h>
struct subsubtest
{
int subsub1;
char *subsub2;
};

struct subtest {

	int sub1;
	long sub2;
	char* substr1;//H
	struct subsubtest *substu;
};
struct test{

	int high; //H 4
	int b; //4
	char *str1; //H 8
	char *str2; //8
	const struct subtest *stu;
	//struct subtest stu1;

};


void fuzztest(struct test *arg1,int arg2){
	struct test mem_arg1;
	arg1=&mem_arg1;
	
	struct test mem_arg1_copy;
	struct test *arg1_copy;
	arg1_copy=&mem_arg1_copy;
	
	arg1_copy->b=arg1->b;
	
	struct subtest memsub;
	struct subtest memsub_copy;
	arg1->stu=&memsub;
	arg1->stu=&memsub_copy;
	arg1_copy->stu->sub1=arg1->stu->sub1;
	
	
	
	
	
	
	
}

int main()
{
	
	
	
	
}
