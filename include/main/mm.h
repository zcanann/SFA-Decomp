#ifndef MAIN_MM_H_
#define MAIN_MM_H_

#include "ghidra_import.h"

int alignUp2(int value);
int roundUpTo4(int value);
int roundUpTo8(int value);
int roundUpTo16(int value);
int roundUpTo32(int value);
void mm_free(void *ptr);
void *mmAlloc(int size, int type, int flag);
void* getCache(void);
void cacheQueueWait(int sync);
void copyToCache(void* dst, void* src, u32 count);
void memcpyToCache(void* dst, void* src, u32 count);
void texFlagFn_80023cbc(int value);
void AtomicSList_Push(void** list, void* node);
void* AtomicSList_Pop(void** list);
int printHeapStats(int mode);
void* stackCreate(int count, int size);


/* extern-cleanup: defining-file public prototypes */
void mmFree(void* p);
void mmFreeDeferred(void* p);
void mmInit(void);

int mmSetFreeDelay(int v);
int testAndSet_onlyUseHeaps1and2(int v);
int testAndSet_onlyUseHeap3(int v);
int mmGetRegionForPtr(u8* ptr);
int getHeapItemSize(void* ptr);
void mmFreeTick(int arg);
int mmCreateMemoryStore(int size);
void* mmAllocateFromFBMemoryStore(int handle, int size);

#endif /* MAIN_MM_H_ */
