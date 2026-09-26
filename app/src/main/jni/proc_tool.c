#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

#include "proc_tool.h"
#include "log_marco.h"

/**
 * get target process name.
 *  pid  = -1, get self
 *  pid != -1, get target process
 * return: process_name
 */
char* proc_get_process_name(pid_t pid)
{
    FILE* fp = NULL;
    char path[MAX_LENGTH] = {0};
    static char buffer[MAX_LENGTH] = {0};

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    if(0 > pid){
        snprintf(path, sizeof(path), "/proc/self/cmdline");
    }
    else{
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    }

    fp = fopen(path, "r");
    if(NULL == fp) fatal("[-] fopen:[%s], errno:[%s]", path, strerror(errno));
    if(NULL == fgets(buffer, sizeof(buffer), fp)) fatal("[-] fgets errno:[%s]", strerror(errno));
        
#undef fatal
    fclose(fp);
    return buffer;

ERR_EXIT:
    if(NULL != fp) fclose(fp);
    return NULL;
}

/**
 * get moduleBase from /proc/pid/maps
 *  pid  = -1, get self
 *  pid != -1, get target process
 *  moduleName -> module name
 * return base_addr
 */
void* proc_get_module_base(pid_t pid, const char* module_name)
{
    FILE* fp = NULL;
    char path[MAX_LENGTH] = {0};
    char line[MAX_LENGTH] = {0};
    unsigned long prev_end = 0;
    unsigned long base_addr = 0;
    int found_elf = 0;

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    if(NULL == module_name) return NULL;

    if(pid < 0){
        snprintf(path, sizeof(path), "/proc/self/maps");
        pid = getpid();
    }
    else{
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    }

    fp = fopen(path, "r");
    if(NULL == fp) fatal("[-] fopen:[%s], errno:[%s]", path, strerror(errno));
    
    while(fgets(line, sizeof(line), fp)){
        if(!strstr(line, module_name)) continue;
        
        unsigned long start, end;
        char perms[5], offset[9], dev[6], inode[9];
        char pathname[MAX_LENGTH];
        
        if(sscanf(line, "%lx-%lx %4s %8s %5s %8s %255[^\n]", 
                  &start, &end, perms, offset, dev, inode, pathname) < 6) continue;
        
        if(strcmp(offset, "00000000") == 0 && strstr(pathname, module_name)){
            char mem_path[MAX_LENGTH];
            snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
            
            FILE* mem_fp = fopen(mem_path, "rb");
            if(mem_fp){
                fseek(mem_fp, start, SEEK_SET);
                uint32_t magic;
                fread(&magic, sizeof(magic), 1, mem_fp);
                fclose(mem_fp);
                
                if(magic == 0x464C457F){
                    if(found_elf && prev_end == start){
                        base_addr = start;
                        break;
                    }
                    found_elf = 1;
                    base_addr = start;
                }
                else{
                    found_elf = 0;
                    base_addr = 0;
                }
            }
        }
        prev_end = end;
    }

#undef fatal
    fclose(fp);
    return base_addr ? (void*)base_addr : NULL;

ERR_EXIT:
    if(NULL != fp) fclose(fp);
    return NULL;    
}

/**
 * get target process fun addr
 *  pid:         target process pid
 *  module_name: target module name
 *  local_addr:  local fun addr
 * return remote_addr
 */
void* proc_get_remote_fun_addr(pid_t pid, const char* module_name, void* local_addr)
{
    void* local_module_base = NULL;
    void* remote_module_base = NULL;
    char* remote_addr = NULL;

#define fatal(fmt, args...) do {LOGE(fmt, ##args); goto ERR_EXIT;} while(0)

    local_module_base = proc_get_module_base(-1, module_name);
    if(NULL == local_module_base) fatal("[-] get local module base failed");
    remote_module_base = proc_get_module_base(pid, module_name);
    if(NULL == remote_module_base) fatal("[-] get remote module base failed");
    remote_addr = (char*)remote_module_base + ((char*)local_addr - (char*)local_module_base);

#undef fatal    
    return (void*)remote_addr;

ERR_EXIT:
    return NULL;    
}