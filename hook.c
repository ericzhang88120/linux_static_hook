#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <signal.h>
#include <string>
#include <string.h>
#include "hook.h"

int is_target = 1;

//64 bit jmp code
char jmp_code[12] ={0x48, 0xb8, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xe0};
char target[128]="";


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
		std::size_t trim = str.find("\n");
		

		std::string value = str.substr(pos+1,trim-pos-1);
		std::string key = str.substr(0,pos);

		
		if(strcmp(key.c_str(),"FUNC") == 0)
		{
			//get the function name
			strcpy(funcname,value.c_str());
		}
		if(strcmp(key.c_str(),"PATH") == 0)
		{
			//get the function name
			strcpy(target,value.c_str());
		}
		
	}
	return 0;
}
void set_page_rw(void * addr, size_t i_len)
{
    //printf("beign to set page rw\n");
    size_t page_size = getpagesize();    
    size_t i_page = (size_t)addr & ~(getpagesize() - 1);    
    size_t i_page_end = (size_t)((char*)addr + i_len) & ~(getpagesize()  - 1);    
    size_t i;

	printf("######## %d-----%d----------%p\n",i_page,i_page_end,addr);
    for(i=i_page; i<=i_page_end; i += page_size)
    {        
        int iRet = mprotect((char*)i, page_size, PROT_READ|PROT_WRITE|PROT_EXEC);        
        if(iRet != 0)
        {            
            printf("mprotect return %s", strerror(iRet));        
        }    
    }
}
void restore_func(hook_func* func)
{

    void * old_address = func->address_old;

    memcpy(old_address, func->back, 12);
}

void replace_func(hook_func* func)
{

    void * old_address = func->address_old;
    void * new_address = func->address_new;

    printf("begin to set address readable\n");
    set_page_rw(old_address, 12);
    printf("fin set address readable\n");
    memcpy(func->back, old_address, 12);
    memcpy(jmp_code+2, &new_address, sizeof(void*)); //replace jmp code
    memcpy(old_address, jmp_code, 12);
}

void * find_func(int pid, char* funcname)
{
	void* address;
	char shell_buffer [128];
	char process_name[128];
	memset(process_name,0,sizeof(process_name));
	int cnt = readlink("/proc/self/exe", process_name, 128);
	if(cnt == -1)
	{
		printf("fail to get the process path");
	}
	
	snprintf(shell_buffer, 128, "nm -C %s|grep %s|awk {'print $1'}", process_name, funcname);
	printf("shell buffer is %s\n", shell_buffer);
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
        printf("process load so succeed, pid is %d \n", pid);
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
//    hook_user_func(HookfuncName);
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


