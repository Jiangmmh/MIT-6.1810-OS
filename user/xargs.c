#include "kernel/types.h"
#include "user/user.h"
#include "kernel/param.h"

char* args[MAXARG];
int main(int argc, char* argv[]) {
    char buf[512];
    int i, pid;
    for (i = 0; i < argc - 1; i++) {
        args[i] = (char*)malloc(512);
        strcpy(args[i], argv[i + 1]);
    }
    
    args[i] = (char*)malloc(512);
    while(gets(buf, 512)[0]) {
        uint len = strlen(buf);
        if (buf[len-1] == '\n' || buf[len-1] == '\r') { // 剔除多余的换行
            buf[len-1] = 0;
        }

        pid = fork();   // 创建子进程，每行执行一次
        if (pid == 0) {    
            strcpy(args[i++], buf);
            args[i] = 0;
            exec(args[0], args);
        } else {
            wait(0);
        }
    }

    for (int j = 0; j < i; j++) {
        free(args[j]);
    }
    
    return 0;
}
