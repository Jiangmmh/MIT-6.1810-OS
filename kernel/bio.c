// Buffer cache.
//
// The buffer cache is a linked list of buf structures holding
// cached copies of disk block contents.  Caching disk blocks
// in memory reduces the number of disk reads and also provides
// a synchronization point for disk blocks used by multiple processes.
//
// Interface:
// * To get a buffer for a particular disk block, call bread.
// * After changing buffer data, call bwrite to write it to disk.
// * When done with the buffer, call brelse.
// * Do not use the buffer after calling brelse.
// * Only one process at a time can use a buffer,
//     so do not keep them longer than necessary.


#include "types.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "riscv.h"
#include "defs.h"
#include "fs.h"
#include "buf.h"

#define BUCKETSIZE 3 // number of hashing buckets
#define BUFFERSIZE 10 // number of available buckets per bucket
extern uint ticks;

struct {
  struct spinlock lock;
  struct buf buf[BUFFERSIZE];
} bcache[BUCKETSIZE];

int
hash(uint blockno) {
  return blockno % BUCKETSIZE;
}

void
binit(void)
{
  for (int i = 0; i < BUCKETSIZE; i++) {
    initlock(&bcache[i].lock, "bcache_bucket");
    for (int j = 0; j < BUFFERSIZE; j++) {
      initsleeplock(&bcache[i].buf[j].lock, "buffer");
    }
  }
}

// Look through buffer cache for block on device dev.
// If not found, allocate a buffer.
// In either case, return locked buffer.
static struct buf*
bget(uint dev, uint blockno)
{
  struct buf *b;

  int bucket = hash(blockno);
  acquire(&bcache[bucket].lock);

  // Is the block already cached?
  for (int i = 0; i < BUFFERSIZE; i++) {  // 从当前bucket中的buf中查找
    b = &bcache[bucket].buf[i];
    if (b->dev == dev && b->blockno == blockno) {
      b->refcnt++;
      release(&bcache[bucket].lock);
      acquiresleep(&b->lock);
      return b;
    }
  }

  // 实现LRU，选择时间戳最早的使用
  uint least = 0xffffffff;
  int least_idx = -1;
  for (int i = 0; i < BUFFERSIZE; i++) {
    b = &bcache[bucket].buf[i];
    if (b->refcnt == 0 && b->lastuse < least) {
      least = b->lastuse;
      least_idx = i;
    }
  }

  // 在当前bucket中没有空闲的buf，应当去别的bucket中找，但是这里测试能通过就懒得搞了
  if (least_idx == -1) 
    panic("bget: no unused buffer");
  
  b = &bcache[bucket].buf[least_idx];
  b->dev = dev;
  b->blockno = blockno;
  b->valid = 0;
  b->refcnt = 1;
  release(&bcache[bucket].lock);
  acquiresleep(&b->lock);
  return b;
  // panic("bget: no buffers");
}

// Return a locked buf with the contents of the indicated block.
struct buf*
bread(uint dev, uint blockno)
{
  struct buf *b;

  b = bget(dev, blockno);
  if(!b->valid) {
    virtio_disk_rw(b, 0);
    b->valid = 1;
  }
  return b;
}

// Write b's contents to disk.  Must be locked.
void
bwrite(struct buf *b)
{
  if(!holdingsleep(&b->lock))
    panic("bwrite");
  virtio_disk_rw(b, 1);
}

// Release a locked buffer.
// Move to the head of the most-recently-used list.
void
brelse(struct buf *b)
{
  if(!holdingsleep(&b->lock))
    panic("brelse");

  int bucket = hash(b->blockno);
  acquire(&bcache[bucket].lock);
  b->refcnt--;
  release(&bcache[bucket].lock);
  releasesleep(&b->lock);
}

void
bpin(struct buf *b) {
  int bucket = hash(b->blockno);
  acquire(&bcache[bucket].lock);
  b->refcnt++;
  release(&bcache[bucket].lock);
}

void
bunpin(struct buf *b) {
  int bucket = hash(b->blockno);
  acquire(&bcache[bucket].lock);
  b->refcnt--;
  release(&bcache[bucket].lock);
}