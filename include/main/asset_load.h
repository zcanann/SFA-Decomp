#ifndef MAIN_ASSET_LOAD_H_
#define MAIN_ASSET_LOAD_H_

#include "ghidra_import.h"

struct ObjAnimDef;

void getTabEntry(void *dst, int fileId, int offset, int size);
int fileLoadToBufferOffset(int fileId, void *dst, int offset, int size);
void loadAssetFileById(void* out, int fileId);
void loadTextureFile(void** out, int assetId);
void animationLoad(void** out, int animId, int moveIndex, u8* cache, struct ObjAnimDef* animDef);

#endif /* MAIN_ASSET_LOAD_H_ */
