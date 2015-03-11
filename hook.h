#ifndef __HOOK_H__
#define __HOOK_H__

#include "func.h"
void* find_func(int pid, char* funcname); 
void replace_func(hook_func* func);
void restore_func(hook_func* func);
int detect_target();
void set_page_rw(void * addr, size_t i_len);

#endif