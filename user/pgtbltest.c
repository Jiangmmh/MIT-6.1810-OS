#include "kernel/param.h"
#include "kernel/fcntl.h"
#include "kernel/types.h"
#include "kernel/riscv.h"
#include "user/user.h"

#define N (8 * (1 << 20)) // 4个超级页

void print_pgtbl();
void print_kpgtbl();
void ugetpid_test();
void superpg_test();

int
main(int argc, char *argv[])
{
  print_pgtbl();
  ugetpid_test();
  print_kpgtbl();
  superpg_test();
  printf("pgtbltest: all tests succeeded\n");
  exit(0);
}

char *testname = "???";

void
err(char *why)
{
  printf("pgtbltest: %s failed: %s, pid=%d\n", testname, why, getpid());
  exit(1);
}

void
print_pte(uint64 va)
{
    pte_t pte = (pte_t) pgpte((void *) va);   // 调用系统调用pgpte，得到va对应的页表项
    printf("va 0x%lx pte 0x%lx pa 0x%lx perm 0x%lx\n", va, pte, PTE2PA(pte), PTE_FLAGS(pte));
}

void
print_pgtbl()
{
  printf("print_pgtbl starting\n");
  for (uint64 i = 0; i < 10; i++) { // 打印虚拟地址空间前10个页面
    print_pte(i * PGSIZE);
  }
  uint64 top = MAXVA/PGSIZE;
  for (uint64 i = top-10; i < top; i++) { // 打印虚拟地址空间后10个页面
    print_pte(i * PGSIZE);
  }
  printf("print_pgtbl: OK\n");
}

void
ugetpid_test()
{
  int i;

  printf("ugetpid_test starting\n");
  testname = "ugetpid_test";

  for (i = 0; i < 64; i++) {
    int ret = fork();
    if (ret != 0) {
      wait(&ret);
      if (ret != 0)
        exit(1);
      continue;
    }
    if (getpid() != ugetpid())
      err("missmatched PID");
    exit(0);
  }
  printf("ugetpid_test: OK\n");
}

void
print_kpgtbl()
{
  printf("print_kpgtbl starting\n");
  kpgtbl();
  printf("print_kpgtbl: OK\n");
}


void
supercheck(uint64 s)
{
  // printf("DEBUG: supercheck start\n");
  pte_t last_pte = 0;

  for (uint64 p = s;  p < s + 512 * PGSIZE; p += PGSIZE) { // 同一个超级快
    pte_t pte = (pte_t) pgpte((void *) p);  
    if(pte == 0)
      err("no pte");
    if ((uint64) last_pte != 0 && pte != last_pte) { // 同一个超级块内的地址，查找到的PTE应该都是相同的
        err("pte different");
    }
    if((pte & PTE_V) == 0 || (pte & PTE_R) == 0 || (pte & PTE_W) == 0){ // level1-PTE必须为WR
      err("pte wrong");
    }
    last_pte = pte;
  }

  for(int i = 0; i < 512; i += PGSIZE){
    *(int*)(s+i) = i;
  }

  for(int i = 0; i < 512; i += PGSIZE){
    if(*(int*)(s+i) != i)
      err("wrong value");
  }
  // printf("DEBUG: supercheck done\n");
}

void
superpg_test()
{
  int pid;
  
  printf("superpg_test starting\n");
  testname = "superpg_test";
  
  char *end = sbrk(N);  // 利用sbrk申请8M的内存
  if (end == 0 || end == (char*)0xffffffffffffffff)
    err("sbrk failed");

  uint64 s = SUPERPGROUNDUP((uint64) end);
  supercheck(s);  // 检查超级页
  print_kpgtbl();
  if((pid = fork()) < 0) {
    err("fork");
  } else if(pid == 0) {
    supercheck(s);  // 检查子进程    
    exit(0);
  } else {
    int status;
    wait(&status);
    if (status != 0) {
      exit(0);
    }
  }
  printf("superpg_test: OK\n");  
}
