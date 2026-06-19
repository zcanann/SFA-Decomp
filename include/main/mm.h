#ifndef MAIN_MM_H_
#define MAIN_MM_H_

#include "ghidra_import.h"

int roundUpTo4(int value);
int roundUpTo8(int value);
void mm_free(void *ptr);
void *mmAlloc(int size, int type, int flag);
u8 *getCache(void);
void cacheQueueWait(int sync);
void copyToCache(void *dst, void *src, int count);
void memcpyToCache(void *dst, void *src, int count);


/* extern-cleanup: defining-file public prototypes */
void mmFree(void* p);
void mmFreeDeferred(void* p);
void mmInit(void);

#endif /* MAIN_MM_H_ */
