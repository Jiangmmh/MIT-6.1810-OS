#include "kernel/types.h"
#include "user/user.h"

void helper(int p) {
    int cur, pp[2], len, buf;
    if (read(p, &cur, 4) <= 0) {
        exit(0);
    }

    pipe(pp);
    if (fork() == 0) {  // child
        close(p);
        close(pp[1]);
        helper(pp[0]);
    } else {    // parent
        close(pp[0]);
        printf("prime %d\n", cur);
        while ((len = read(p, &buf, 4)) > 0) {
            if (buf % cur != 0) {
                write(pp[1], &buf, 4);
            }
        }
        close(p);
        close(pp[1]);
        wait(0);
    }
}

int main() {
    int p[2];
    int pid, i = 2;
    pipe(p);

    if ((pid = fork()) == 0) {    // child
        close(p[1]);
        helper(p[0]);
    } else {    // parent
        close(p[0]);
        printf("prime %d\n", i++);
        while (i <= 280) {
            if (i % 2 != 0) {
                write(p[1], &i, 4);
            }
            i++;
        }
        close(p[1]);
        wait(0);
    }
}
