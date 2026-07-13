#ifndef MAIN_ASSET_LOAD_H_
#define MAIN_ASSET_LOAD_H_

#include "ghidra_import.h"

void *getTabEntry(void *dst, int fileId, int offset, int size);
int fileLoadToBufferOffset(int fileId, void *dst, int offset, int size);
void loadAssetFileById(void* out, int fileId);

#endif /* MAIN_ASSET_LOAD_H_ */
