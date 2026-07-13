#ifndef MAIN_MAP_LOAD_H_
#define MAIN_MAP_LOAD_H_

#include "types.h"

int loadMapAndParent(int mapId);
int lockLevel(s32 val, int idx);
int mapUnload(int mapId, int flags);
int unlockLevel(s32 val, int idx, int flag);
void defragMemory(int mode);
void mapLoadDataFiles(int mapIdx);
void setForceLoadImmediately(void);
void clearForceLoadImmediately(void);

#endif /* MAIN_MAP_LOAD_H_ */
