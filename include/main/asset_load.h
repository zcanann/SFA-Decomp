#ifndef MAIN_ASSET_LOAD_H_
#define MAIN_ASSET_LOAD_H_

#include "ghidra_import.h"

void *getTabEntry(void *dst, int fileId, int offset, int size);
int fileLoadToBufferOffset(int fileId, void *dst, int offset, int size);


/* extern-cleanup: consolidated prototypes */
void* loadCharacter(s16* data, int flags, int arg2, int arg3, void* parent, int unused);
void* loadAnimation(int hdr, s16 id, int b, u8* bufout);
void Obj_InitObjectSystem(void);
void mapInitFn_80069990(void);
void playerUpdateFn_8005649c(void);
void trackIntersect(void);
void doPendingMapLoads(void);
void Pause_SetDisabled(int);

#endif /* MAIN_ASSET_LOAD_H_ */
