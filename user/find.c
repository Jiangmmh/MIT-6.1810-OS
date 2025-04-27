#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fs.h"
#include "kernel/fcntl.h"

char buf[512];

void find(char* path, char* target) {
    char *p, name[512];
    int fd;
    struct dirent de;
    struct stat st;
    
    if ((fd = open(path, O_RDONLY)) < 0) { 
        fprintf(2, "find: cannot open %s\n", path);
        exit(1);
    }

    if (fstat(fd, &st) < 0) {
        fprintf(2, "find: cannot stat %s\n", path);
        close(fd);
        exit(1);
    }
    
    if (st.type != T_DIR) {     // 若path对应的不是目录直接退出
        close(fd);
        exit(1);
    } else {
        strcpy(buf, path);      
        p = buf + strlen(path);
        *p++ = '/';
        while (read(fd, &de, sizeof(de)) == sizeof(de)) {   // 反复读取目录中的文件或目录
            if(de.inum == 0)
                continue;
            strcpy(name, de.name);
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)  // 剔除.和..
                continue;
            
            strcpy(p, name);
            p = p + strlen(name);

            if (stat(buf, &st) < 0) {
                fprintf(2, "find: cannot stat %s\n", buf);
                close(fd);
                exit(1);
            }

            if (st.type == T_FILE) {    // 文件
                if (strcmp(name, target) == 0) {
                    printf("%s\n", buf);
                }
            } else if (st.type == T_DIR) { // 目录，递归find
                find(buf, target);
            }
            p -= strlen(name);  // 回溯
        }
        close(fd);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(2, "Usage: find [path] [filename]\n");
        exit(1);
    }

    find(argv[1], argv[2]);

    return 0;
}