#include "fuzz.h"
using namespace std;
uint8_t copydata[132];
#include "fuzz.h"
using namespace std;
uint8_t copydata[132];
uint8_t preoutlow[132];
char* destlow;
char* srclow;
int* lenlow;
int loop=0;
int real_loop=0;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
	char* dest;
	char* src;
	int* len;
	if (loop/1000==0)
	{
		if (size>=132)
		{
			memcpy(copydata,data,size);
			dest=(char*)&copydata[0];
			dest={0};
			src=(char*)&copydata[64];
			copydata[127]='\0';
			len=(int*)&copydata[128];
			if(*(len)>) *len=64;
			memcpy(preoutlow,dest,size);
			loop++;
		}
	}else
	{
		if (size>=4)
		{
		dest=(char*)&copydata[0];
		destlow=(char*)&preoutlow[0];
		src=(char*)&copydata[64];
		srclow=(char*)&preoutlow[64];
		len=(int*)&copydata[128];
		lenlow=(int*)&preoutlow[128];
		len=(int*)&data[0];
		if(*(len)>64) *len=64;
			test_overread(dest,src,*len);
			if(strcmp((const char*)dest,(const char*)destlow)==0){}else {printf("insecure");exit(1);}
			if(strcmp((const char*)src,(const char*)srclow)==0){}else {printf("insecure");exit(1);}
			loop++;
		}
	}
	cout<<real_loop<<"	realloop time.."<<endl;
	cout<<size<<"	size of every time.."<<endl;
	cout<<loop<<"	loop time"<<endl;
	real_loop++;
	return 0;
}
int loop=0;
int real_loop=0;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
int loop=0;
int real_loop=0;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
	char* dest;
	char* src;
	int* len;
		if (size>=132)
		{
		memcpy(copydata,data,size);
int loop=0;
int real_loop=0;


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
 {
	char* dest;
	char* src;
	int* len;
		if (size>=132)
		{
		memcpy(copydata,data,size);
		dest=(char*)&copydata[0];
		copydata[63]='\0';
		src=(char*)&copydata[64];
		copydata[127]='\0';
		len=(int*)&copydata[128];
			test_overread(dest,src,*len);
			loop++;
		}
	cout<<real_loop<<"	realloop time.."<<endl;
	cout<<size<<"	size of every time.."<<endl;
	cout<<loop<<"	loop time"<<endl;
	real_loop++;
	return 0;
}
