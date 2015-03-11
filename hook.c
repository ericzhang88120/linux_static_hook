#include "hook.h"


int read_cfg(char* funcname)
{
	FILE* fp;
	char* line = NULL;
	size_t len =0;
	size_t read = 0;
	fp = fopen("hook.conf", "r");
	if(fp == NULL)
	{
		printf("config file read fail\n");
		return 1;
	}
	while((read = getline(&line,&len,fp))!= -1)
	{
		std::string str = line;
		std::size_t end = str.length();
		std::size_t pos = str.find("=");

		std::string value = str.substr(pos+1);
		std::string key = str.substr(0,pos-1);

		if(key == "FUNC")
		{
			//get the function name
			strcpy(funcname,value.c_str());
		}
	}
	return 0;
}

int detect_target()
{
    int pid=getpid();
    char path_buffer [128];
    snprintf(path_buffer, 128, "/proc/%d/exe1", pid);
    char buffer [128];
    int result = readlink(path_buffer, buffer, 128);
    buffer[result] = 0;
    if (strcmp(target, buffer) == 0) {
        is_target = 1;
        printf("process load so succeed, pid is %d \n", target, pid);
        return 1;
    }else{
        return 0;
    }
}

//run before main
__attribute__((constructor)) void hook_init(){
	char HookfuncName[128];
	memset(HookfuncName,0,sizeof(HookfuncName));
    if(read_cfg(HookfuncName) != 0)
    {
        return ;
    }
    if (detect_target()) 
    {	
        hook_user_func(HookfuncName);
    }
}
//run after main
__attribute__((destructor)) void hook_end(){
    if (is_target == 1) 
    {
        printf("hook end\n");		
    }
}


