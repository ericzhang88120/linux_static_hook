#include <stdio.h>
#include <unistd.h>

void test()
{
	// we will hook this function
	printf("Hello world\n");
}
int main(int argc,char* argv[])
{
	while(true)
	{
		//run a function which is used for hook
		test();
		sleep(1);
	}
	return 0;
}
