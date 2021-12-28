
#include "test_exam.h"
#include <string.h>
#include <stdio.h>

void fuzztest(struct test *arg1,int arg2){
	

	
}

int main()
{
	char data[128];
	memset(data,0,128);
	memcpy(data,"rerer",5);
	printf("%s\n",data);
	
	struct test *p;
	p=(struct test*)&data[0];
	p->str1=(char*)&data[32];
	//cahr * is 16;
	p->stu=(struct subtest*)&data[48];
	
	long *temp1=(long *)&data[64];
	printf("before %d",*temp1);
	
	*temp1=(long)&data[80];
	printf("after %d",*temp1);
	
	long a=900;
	long *ptr1=&a;
	*ptr1=800;
	printf("%d\n",a);
	
	long *temp2=(long *)&data[72];
	*temp2=(long)&data[96];
	
	p->stu->substu->subsub2=(char*)&data[112];
	
	
	
}
