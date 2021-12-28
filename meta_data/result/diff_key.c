#include <stdio.h>
#include <string.h>

char sink_data[20];

void sink_mtd(){
	printf("%s\n",sink_data); //sink
}

char *copy(char *dest, const char* src){
	return strcpy(dest, src); //source
}

void op(char *(str_op)(char *, const char *), const char *buf){
	if( !strcmp(buf,"passwd") ){
		(*str_op)(sink_data,"secret");
		sink_mtd();
	}
}

void dump(){
	printf("dump\n");
}

int main(int argc, char **argv){
	op(copy, argv[1]);
	dump();
	sink_mtd();
	return 0;
}
