#include <stdio.h>

void test()
{
	// we will hook this function
	printf("Hello world\n");
}
int main(int argc,char* argv[])
{
	//run a function which is used for hook
	test();
	return 0;
}
