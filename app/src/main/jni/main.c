#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include "proc_tool.h"
#include "inject.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/procfs.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <malloc.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <inttypes.h>
#include <libgen.h>
#include <jni.h>
#include <android/log.h>

// 函数声明
int get_pid_from_package(const char* package_name);
void print_usage(const char* program_name);
int is_number(const char* str);
void interactive_mode();

int main(int argc, char* argv[])
{
    pid_t pid = 0;
    char* so_name = NULL;
    char* package_name = NULL;
    
    // 如果没有命令行参数，进入交互模式
    if (argc == 1) {
        interactive_mode();
        return 0;
    }
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-pid") == 0 && i + 1 < argc) {
            if (pid != 0 || package_name != NULL) {
                printf("[-] 错误: -pid 和 -pkg 参数只能使用一个\n");
                print_usage(argv[0]);
                return -1;
            }
            pid = atoi(argv[++i]);
        } 
        else if (strcmp(argv[i], "-pkg") == 0 && i + 1 < argc) {
            if (pid != 0 || package_name != NULL) {
                printf("[-] 错误: -pid 和 -pkg 参数只能使用一个\n");
                print_usage(argv[0]);
                return -1;
            }
            package_name = argv[++i];
        } 
        else if (strcmp(argv[i], "-lib") == 0 && i + 1 < argc) {
            so_name = argv[++i];
        }
        else if (strncmp(argv[i], "-pid=", 5) == 0) {
            if (pid != 0 || package_name != NULL) {
                printf("[-] 错误: -pid 和 -pkg 参数只能使用一个\n");
                print_usage(argv[0]);
                return -1;
            }
            pid = atoi(argv[i] + 5);
        }
        else if (strncmp(argv[i], "-pkg=", 5) == 0) {
            if (pid != 0 || package_name != NULL) {
                printf("[-] 错误: -pid 和 -pkg 参数只能使用一个\n");
                print_usage(argv[0]);
                return -1;
            }
            package_name = argv[i] + 5;
        }
        else if (strncmp(argv[i], "-lib=", 5) == 0) {
            so_name = argv[i] + 5;
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        else {
            printf("[-] 未知参数: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }
    
    // 参数验证
    if ((pid == 0 && package_name == NULL) || so_name == NULL) {
        printf("[-] 缺少必要参数\n");
        print_usage(argv[0]);
        return -1;
    }
    
    // 执行注入
    return perform_injection(pid, package_name, so_name);
}

// 交互式模式
void interactive_mode() {
    printf("=======================================\n");
    printf("       SO注入工具 - 交互模式\n");
    printf("=======================================\n\n");
    
    char input[256] = {0};
    pid_t pid = 0;
    char* package_name = NULL;
    char so_path[512] = {0};
    
    // 输入包名或PID
    while (1) {
        printf("请输入目标应用的包名或进程PID: ");
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n[-] 输入错误\n");
            return;
        }
        
        // 去除换行符
        input[strcspn(input, "\n")] = '\0';
        
        if (strlen(input) == 0) {
            printf("[-] 输入不能为空，请重新输入\n");
            continue;
        }
        
        // 判断输入的是否为纯数字（PID）
        if (is_number(input)) {
            pid = atoi(input);
            printf("[+] 使用PID模式: %d\n", pid);
            break;
        } else {
            package_name = strdup(input);
            printf("[+] 使用包名模式: %s\n", package_name);
            break;
        }
    }
    
    // 输入SO文件路径
    while (1) {
        printf("\n请输入要注入的SO文件完整路径: ");
        fflush(stdout);
        
        if (fgets(so_path, sizeof(so_path), stdin) == NULL) {
            printf("\n[-] 输入错误\n");
            if (package_name) free(package_name);
            return;
        }
        
        // 去除换行符
        so_path[strcspn(so_path, "\n")] = '\0';
        
        if (strlen(so_path) == 0) {
            printf("[-] 路径不能为空，请重新输入\n");
            continue;
        }
        
        // 检查文件是否存在
        if (access(so_path, F_OK) == -1) {
            printf("[-] SO文件不存在，请检查路径: %s\n", so_path);
            printf("是否继续? (y/n): ");
            
            char confirm[10];
            fgets(confirm, sizeof(confirm), stdin);
            if (confirm[0] != 'y' && confirm[0] != 'Y') {
                continue;
            }
        }
        
        break;
    }
    
    printf("\n=======================================\n");
    printf("正在准备注入...\n");
    printf("目标: %s\n", package_name ? package_name : "PID");
    printf("PID: %d\n", pid);
    printf("SO文件: %s\n", so_path);
    printf("=======================================\n\n");
    
    // 执行注入
    int result = perform_injection(pid, package_name, so_path);
    
    // 清理资源
    if (package_name) free(package_name);
    
    if (result == 0) {
        printf("\n[+] 注入完成！\n");
    } else {
        printf("\n[-] 注入失败！\n");
    }
}

// 执行注入的通用函数
int perform_injection(pid_t pid, char* package_name, char* so_name) {
    // 如果提供了包名，则通过包名获取PID
    if (package_name != NULL) {
        pid = get_pid_from_package(package_name);
        if (pid <= 0) {
            printf("[-] 无法找到包名 %s 对应的进程，或进程未运行\n", package_name);
            return -1;
        }
        printf("[+] 包名 %s 对应的进程PID: %d\n", package_name, pid);
    }
    
    // 检查SO文件是否存在
    if (access(so_name, F_OK) == -1) {
        printf("[-] SO文件不存在: %s\n", so_name);
        return -1;
    }
    
    printf("[+] 开始注入 [%s] 到 [pid:%d] 进程\n", so_name, pid);
    
    // 禁用SELinux（需要root权限）
    printf("[+] 尝试禁用SELinux...\n");
    system("su -c setenforce 0");
    
    // 执行注入
    if (start_inject(pid, so_name) < 0) {
        printf("[-] 注入失败\n");
        return -1;
    } else {
        printf("[+] 注入成功\n");
    }
    
    fflush(stdout);
    return 0;
}

// 检查字符串是否为纯数字
int is_number(const char* str) {
    if (str == NULL || *str == '\0') {
        return 0;
    }
    
    // 检查每个字符是否为数字
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) {
            return 0;
        }
    }
    return 1;
}

int get_pid_from_package(const char *packageName) {
    int id = -1;
    DIR *dir;
    FILE *fp;
    char filename[64];
    char cmdline[64];
    struct dirent *entry;
    
    dir = opendir("/proc");
    if (dir == NULL) {
        perror("opendir");
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(packageName, cmdline) == 0) {
                    closedir(dir);
                    return id;
                }
            }
        }
    }
    closedir(dir);
    return -1;
}

// 打印使用说明
void print_usage(const char* program_name) {
    printf("=======================================\n");
    printf("       SO注入工具\n");
    printf("=======================================\n\n");
    printf("使用方法:\n");
    printf("  1. 交互模式（无参数）:\n");
    printf("     %s\n\n", program_name);
    printf("  2. 命令行模式:\n");
    printf("     %s -pkg <包名> -lib <SO文件路径>\n", program_name);
    printf("     或\n");
    printf("     %s -pid <进程ID> -lib <SO文件路径>\n", program_name);
    printf("\n");
    printf("参数说明:\n");
    printf("  -pkg <包名>       : 目标应用的包名\n");
    printf("  -pid <进程ID>     : 目标进程的PID\n");
    printf("  -lib <SO文件路径> : 要注入的SO文件路径\n");
    printf("  --help, -h       : 显示此帮助信息\n");
    printf("\n");
    printf("示例:\n");
    printf("  %s -pkg com.example.app -lib /data/local/tmp/libinject.so\n", program_name);
    printf("  %s -pid 1234 -lib /data/local/tmp/libinject.so\n", program_name);
    printf("  %s -pkg=com.example.app -lib=/data/local/tmp/libinject.so\n", program_name);
    printf("\n");
    printf("交互模式说明:\n");
    printf("  1. 输入包名或PID（纯数字视为PID）\n");
    printf("  2. 输入SO文件完整路径\n");
    printf("  3. 自动执行注入\n");
}