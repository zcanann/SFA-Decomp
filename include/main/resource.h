#ifndef MAIN_RESOURCE_H_
#define MAIN_RESOURCE_H_

#include "ghidra_import.h"

typedef struct ResourceDescriptor {
    u8 pad00[0x10];
    void (*acquire)(struct ResourceDescriptor* descriptor);
    void (*release)(void);
    u8 data[0];
} ResourceDescriptor;

typedef void (*ResourceDescriptorCallback)(void);

typedef struct ResourceDescriptorCallbacks7 {
    u32 metadata[4];
    ResourceDescriptorCallback callbacks[7];
} ResourceDescriptorCallbacks7;

typedef struct ResourceDescriptorCallbacks8 {
    u32 metadata[4];
    ResourceDescriptorCallback callbacks[8];
} ResourceDescriptorCallbacks8;

typedef struct ResourceDescriptorCallbacks12 {
    u32 metadata[4];
    ResourceDescriptorCallback callbacks[12];
} ResourceDescriptorCallbacks12;

typedef struct ResourceDescriptorCallbacks11 {
    u32 metadata[4];
    ResourceDescriptorCallback callbacks[11];
} ResourceDescriptorCallbacks11;

typedef struct ResourceDescriptorCallbacks14 {
    u32 metadata[4];
    ResourceDescriptorCallback callbacks[14];
} ResourceDescriptorCallbacks14;

STATIC_ASSERT(sizeof(ResourceDescriptorCallbacks7) == 0x2C);
STATIC_ASSERT(sizeof(ResourceDescriptorCallbacks8) == 0x30);
STATIC_ASSERT(sizeof(ResourceDescriptorCallbacks11) == 0x3C);
STATIC_ASSERT(sizeof(ResourceDescriptorCallbacks12) == 0x40);
STATIC_ASSERT(sizeof(ResourceDescriptorCallbacks14) == 0x48);

extern ResourceDescriptor* gResourceDescriptors[];
extern void* gResourceLoadedHandles[];
extern u16 gResourceRefCounts[];

BOOL Resource_Release(void *handleSlot);
void *Resource_Acquire(u32 id, int unused);
void Resource_ResetRefCounts(void);

#endif /* MAIN_RESOURCE_H_ */
