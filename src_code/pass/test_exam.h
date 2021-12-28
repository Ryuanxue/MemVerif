#ifndef TEST_EXAM_H
#define TEST_EXAM_H

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

void fuzztest(struct test *arg1,int arg2);

#endif
