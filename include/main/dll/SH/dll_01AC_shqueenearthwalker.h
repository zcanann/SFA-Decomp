#ifndef MAIN_DLL_SH_DLL_01AC_SHQUEENEARTHWALKER_H_
#define MAIN_DLL_SH_DLL_01AC_SHQUEENEARTHWALKER_H_

#include "ghidra_import.h"
#include "main/obj_placement.h"

typedef struct QueenEarthWalkerMapData {
  ObjPlacement base;
  s8 yawByte;
} QueenEarthWalkerMapData;

STATIC_ASSERT(offsetof(QueenEarthWalkerMapData, yawByte) == 0x18);

typedef struct QueenEarthWalkerState {
    /* 0x00 */ u8 stateIndex;
    /* 0x01 */ u8 pad01;
    /* 0x02 */ u8 flags;
    /* 0x03 */ u8 pad03[0x08 - 0x03];
    /* 0x08 */ u8 eyeAnimEnabled;     /* eye-anim sub-struct base; set to 1 to enable eye tracking */
    /* 0x09 */ u8 pad09[0x0c - 0x09];
    /* 0x0C */ f32 targetX;
    /* 0x10 */ f32 targetY;
    /* 0x14 */ f32 targetZ;
    /* 0x18 */ u8 pad18[0x38 - 0x18];
    /* 0x38 */ u8 *eventTable;
    /* 0x3C */ f32 attackTimer;
} QueenEarthWalkerState;

int sh_queenearthwalker_getExtraSize(void);
void sh_queenearthwalker_update(void *obj);
void queenFeedFn_801d44a4(void *obj, void *state);
void openPortalFn_801d4364(void *obj, void *state);
void sh_queenearthwalker_init(void *obj, QueenEarthWalkerMapData *mapData);

#endif /* MAIN_DLL_SH_DLL_01AC_SHQUEENEARTHWALKER_H_ */
