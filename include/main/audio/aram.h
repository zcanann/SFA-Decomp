#ifndef MAIN_AUDIO_ARAM_H_
#define MAIN_AUDIO_ARAM_H_

#include "ghidra_import.h"

void aramQueueCallback(void *req);
void aramUploadData(u32 src, u32 dst, u32 size, u32 mode, u32 callback, u32 callbackArg);
void aramSyncTransferQueue(void);
void aramInit(u32 extraSize);
void aramGetZeroBuffer(void);
u32 aramGetBaseAddress(void);
u32 aramStoreData(void *src, u32 size);
void aramRemoveData(void *unused, u32 size);
void aramInitStreamBuffers(void);
u32 aramGetStreamBufferAddress(u8 idx, u32 *outPos);

#endif /* MAIN_AUDIO_ARAM_H_ */
