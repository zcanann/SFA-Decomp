#ifndef MAIN_RESOURCE_H_
#define MAIN_RESOURCE_H_

#include "ghidra_import.h"

typedef struct ResourceDescriptor {
    u8 pad00[0x10];
    void (*acquire)(struct ResourceDescriptor* descriptor);
    void (*release)(void);
    u8 data[0];
} ResourceDescriptor;

extern ResourceDescriptor* gResourceDescriptors[];

BOOL Resource_Release(void *handleSlot);
void *Resource_Acquire(u32 id, int unused);
void Resource_ResetRefCounts(void);

#endif /* MAIN_RESOURCE_H_ */
