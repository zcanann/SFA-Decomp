#ifndef MAIN_RESOURCE_H_
#define MAIN_RESOURCE_H_

#include "ghidra_import.h"

BOOL Resource_Release(void *handleSlot);
void *Resource_Acquire(u32 id, int unused);
void Resource_ResetRefCounts(void);

#endif /* MAIN_RESOURCE_H_ */
