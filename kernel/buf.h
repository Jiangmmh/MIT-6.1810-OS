struct buf {
  int valid;   // has data been read from disk?
  int disk;    // does disk "own" buf? 是否写到了磁盘
  uint dev;
  uint blockno;
  struct sleeplock lock;
  uint refcnt;
  struct buf *prev; // LRU cache list
  struct buf *next;
  uchar data[BSIZE];
};

