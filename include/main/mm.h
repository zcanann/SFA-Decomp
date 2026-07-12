#ifndef MAIN_MM_H_
#define MAIN_MM_H_

#include "ghidra_import.h"

int roundUpTo4(int value);
int roundUpTo8(int value);
void mm_free(void *ptr);
void *mmAlloc(int size, int type, int flag);
void* getCache(void);
void cacheQueueWait(int sync);
void copyToCache(void* dst, void* src, u32 count);
void memcpyToCache(void* dst, void* src, u32 count);


/* extern-cleanup: defining-file public prototypes */
void mmFree(void* p);
void mmFreeDeferred(void* p);
void mmInit(void);

int mmSetFreeDelay(int v);
int testAndSet_onlyUseHeap3(int v);
void mmFreeTick(int arg);
int mmCreateMemoryStore(int size);
void* mmAllocateFromFBMemoryStore(int handle, int size);

/* Compatibility views for compiler-sensitive callers recovered with legacy types. */
#define mmAllocTagged(size, tag, name) \
    ((void* (*)(u32, u32, void*))mmAlloc)((size), (tag), (name))
#define testAndSetOnlyUseHeap3_u8(value) \
    ((u8 (*)(int))testAndSet_onlyUseHeap3)(value)
#define mmFreeLegacyNoArg() ((void (*)(void))mm_free)()

#endif /* MAIN_MM_H_ */
