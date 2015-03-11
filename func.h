#ifndef __FUNC_H__
#define __FUNC_H__

#include <string.h>
#include <string>
#include <stdio.h>
#include <unistd.h>

#define HOOK_FUNC_MAX 10
#define FUNC_NAME_LENG 128

typedef struct _hook_func {
    void* address_new; 
    void* address_old; 
    char back[12];
    char func_name[FUNC_NAME_LENG];
} hook_func;

void hook_user_func(const char* funcName);

#endif