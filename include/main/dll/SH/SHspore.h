#ifndef MAIN_DLL_SH_SHSPORE_H_
#define MAIN_DLL_SH_SHSPORE_H_

#include "ghidra_import.h"
#include "main/obj_placement.h"

typedef struct QueenEarthWalkerMapData {
  ObjPlacement base;
  s8 yawByte;
} QueenEarthWalkerMapData;

STATIC_ASSERT(offsetof(QueenEarthWalkerMapData, yawByte) == 0x18);

int sh_queenearthwalker_getExtraSize(void);
void sh_queenearthwalker_update(void *obj);
void queenFeedFn_801d44a4(void *obj, void *state);
void openPortalFn_801d4364(void *obj, void *state);
void sh_queenearthwalker_init(void *obj, QueenEarthWalkerMapData *mapData);

#endif /* MAIN_DLL_SH_SHSPORE_H_ */
