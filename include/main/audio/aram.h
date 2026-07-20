#ifndef MAIN_AUDIO_ARAM_H_
#define MAIN_AUDIO_ARAM_H_

#include "ghidra_import.h"

typedef void* (*AramUploadCallback)(u32 sourceOffset, u32 size);

extern AramUploadCallback aramUploadCallback;
extern u32 aramUploadChunkSize;

void aramInit(u32 extraSize);
void aramExit(void);
u32 aramGetBaseAddress(void);
u32 aramStoreData(void *src, u32 size);
void aramRemoveData(void *unused, u32 size);
void aramInitStreamBuffers(void);
u32 aramGetStreamBufferAddress(u8 idx, u32 *outPos);

#endif /* MAIN_AUDIO_ARAM_H_ */
