#include "fuzz.h"
using namespace std;
uint8_t copydata[196];
uint8_t preoutlow[196];
struct test* arg1low;
int* arg2low;
int loop=0;
int real_loop=0;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
	struct test* arg1;
	int* arg2;
	if (loop/1000==0)
	{
		if (size>=196)
		{
			memcpy(copydata,arg1,size);
			arg1=(struct test*)&copydata[0];
			arg1->str1=(char**)&copydata[32];
			*(arg1->str1) = (char*)&data[40];
			char* str1__=*(arg1->str1);
			arg1->str2=(char*)&copydata[40];
			arg1->stu=(struct subtest*)&copydata[104];
			uint8_t *_point_substr1=&copydata[120];
			long *_point_to_substr1=(long*)_point_substr1;
			*_point_to_substr1=(long)&copydata[128];
			arg2=(int*)&copydata[192];
			fuzztest(arg1,*arg2);
			memcpy(preoutlow,arg1,size);
			loop++;
		}
	}else
	{
		if (size>=132)
		{
			arg1=(struct test*)copydata[0];
			arg1low=(struct test*)preoutlow[0];
			arg2=(int*)copydata[192];
			arg2low=(int*)preoutlow[192];
			arg1->high=(int)data[0];
			arg1->str1=(char**)&data[4];
			arg1->stu->substr1=(char*)&data[68];
			fuzztest(arg1,*arg2);
			if(arg1->b==arg1low->b){}else printf("insecure");
			if(strcmp(arg1->str2,arg1low->str2)==0){}else printf("insecure");
			if(arg1->stu->sub1==arg1low->stu->sub1){}else printf("insecure");
			if(arg1->stu->sub2==arg1low->stu->sub2){}else printf("insecure");
			if(*(arg2)==*(arg2low)){}else printf("insecure");
			loop++;
		}
	}
	cout<<real_loop<<"	realloop time.."<<endl;
	cout<<size<<"	size of every time.."<<endl;
	cout<<loop<<'	loop time';
	return 0;
	real_loop++;
}
