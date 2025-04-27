#include "kernel/types.h"
#include "user/user.h"

int main() {
    int p1[2], p2[2];
    int pid;
    char buf, byte = 0x66;   // a byte for send/recv
    
    pipe(p1);   // c->p
    pipe(p2);   // p->c

    pid = fork();
    if (pid == 0) {  // child
        close(p1[0]);
        close(p2[1]);
        read(p2[0], &buf, 1);
        printf("%d: received ping\n", getpid());
        write(p1[1], &buf, 1);
    } else {    // parent
        close(p1[1]);
        close(p2[0]);
        write(p2[1], &byte, 1);
        read(p1[0], &buf, 1);
        printf("%d: received pong\n", getpid());
    }
    exit(0);
}