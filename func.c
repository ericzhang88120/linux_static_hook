#include "func.h"
#include "hook.h"

int hook_func_num = 0;
hook_func my_hook_func;

//define which your own function which is used to replace
void (*myhookfunc)();//define a function point


void Myhook()
{
	printf("My hook func is running\n");
}

void hook_user_func(const char* funcName)
{
	int pid = getpid();//get the process id
	memset(&my_hook_func,0,sizeof(hook_func));//initialize 

	strcpy(my_hook_func.func_name,funcName);//copy function name to the struct
	printf("##hook function name is %s\n");

	//define old and new func point address
	void* address_old;
	void* address_new;
	//first find hook function address
	address_old = find_func(pid, my_hook_func.func_name);
	if(address_old == NULL)
	{
		printf("Old address can not be found\n");
		return;
	}
	myhookfunc = Myhook;
	address_new = (void*)myhookfunc;
	pirntf("debug: old address %p new address %p\n",address_old,address_new);
	//second replace it
	replace_func(&my_hook_func);
	printf("replace_func succeed\n");
	
	
	
}



