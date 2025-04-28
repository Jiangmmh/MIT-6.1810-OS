#include "kernel/types.h"
#include "kernel/fcntl.h"
#include "user/user.h"
#include "kernel/riscv.h"

int
main(int argc, char *argv[])
{
  // your code here.  you should write the secret to fd 2 using write
  // (e.g., write(2, secret, 8)
  char *end = sbrk(PGSIZE*32);    // 申请32个页
  end = end + 16 * PGSIZE;
  end += 7;
  write(1, end, 8);
  write(1, "\n", 1);
  write(2, end, 8);
  
  exit(1);
}
