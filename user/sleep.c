#include "kernel/types.h"
#include "user/user.h"


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: sleep [num_ticks]\n");
        exit(1);
    }

    int num_ticks = atoi(argv[1]);
    sleep(num_ticks);
    exit(0);
}