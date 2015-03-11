#include "hook.h"

int is_target = 1;



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
void * find_func(int pid, char* funcname)
{
    void* address;
    char shell_buffer [128];
    snprintf(shell_buffer, 128, "./proinfo.sh %d %s\n", pid, funcname);
    printf("shell buffer is %s", shell_buffer);
    char buffer [128];
    
    /*
    important, if you make printf in the so logic  before  detect target, here run the proinfo.sh will also printf something
    which will be read by the next fgets
    so never print before detect it's your target
    */
    FILE * fp = popen(shell_buffer, "r");
    if(NULL == fp) {
        perror("popen error");
        return  NULL;
    }
    printf("popen:%s succeed\n",shell_buffer);

    char* ret = fgets(buffer, sizeof(buffer), fp);
    if(NULL == ret) {
        perror("fget error");
        return NULL;
    }
    if(0 == ret){
        printf("the hook func not exist in target");
        return NULL;

    }
    printf("fgets:%s succeed\n",buffer);
    printf("function address is %s\n", buffer);
    pclose(fp);

    if ('\n' == buffer[strlen(buffer)-1]) {
        buffer[strlen(buffer)-1] = '\0';
    }

    sscanf(buffer, "%016lx", &address);
    return address;
}

int detect_target()
{
    int pid=getpid();
    char path_buffer [128];
    snprintf(path_buffer, 128, "/proc/%d/exe", pid);
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
    hook_user_func(HookfuncName);
    /*
    if (detect_target()) 
    {	
        hook_user_func(HookfuncName);
    }
    */
}
//run after main
__attribute__((destructor)) void hook_end(){
    if (is_target == 1) 
    {
        printf("hook end\n");		
    }
}


