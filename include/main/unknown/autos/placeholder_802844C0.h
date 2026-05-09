#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802844C0_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802844C0_H_

#include "ghidra_import.h"

u32 aramStoreData(void *src, u32 size);
void aramRemoveData(void *unused, u32 size);
void aramInitStreamBuffers(void);
u32 aramGetStreamBufferAddress(u8 idx, u32 *outPos);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802844C0_H_ */
