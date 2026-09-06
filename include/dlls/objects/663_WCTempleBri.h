#ifndef DLLS_OBJECTS_663_WCTEMPLEBRI_H_
#define DLLS_OBJECTS_663_WCTEMPLEBRI_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "types.h"
#include "main/objseq.h"
#include "game/objects/object_setup.h"

typedef struct WCTempleBriSetup {
    ObjPlacement base;
    s8 type;
    s8 modelIndex;
    u8 pad1A[4];
    s16 solvedBit;
    u8 pad20[4];
} WCTempleBriSetup;

typedef struct WCTempleBriState {
    f32 minZ;
    f32 sortedOffsets[15];
    u8 partFlags[15];
    u8 partCount;
    u8 partAlpha[15];
    u8 active;
    u16 wavePhaseA;
    u16 wavePhaseB;
    u8 pad64[2];
    u8 flags;
    u8 pad67;
} WCTempleBriState;

STATIC_ASSERT(sizeof(WCTempleBriState) == 0x68);
STATIC_ASSERT(sizeof(WCTempleBriSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTempleBriState, minZ) == 0x00);
STATIC_ASSERT(offsetof(WCTempleBriState, sortedOffsets) == 0x04);
STATIC_ASSERT(offsetof(WCTempleBriState, partFlags) == 0x40);
STATIC_ASSERT(offsetof(WCTempleBriState, partCount) == 0x4f);
STATIC_ASSERT(offsetof(WCTempleBriState, partAlpha) == 0x50);
STATIC_ASSERT(offsetof(WCTempleBriState, active) == 0x5f);
STATIC_ASSERT(offsetof(WCTempleBriState, wavePhaseA) == 0x60);
STATIC_ASSERT(offsetof(WCTempleBriState, wavePhaseB) == 0x62);
STATIC_ASSERT(offsetof(WCTempleBriState, flags) == 0x66);
STATIC_ASSERT(offsetof(WCTempleBriSetup, type) == 0x18);
STATIC_ASSERT(offsetof(WCTempleBriSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCTempleBriSetup, solvedBit) == 0x1e);

void wctemplebri_updateModelWarp(GameObject* obj, WCTempleBriState* state);
int wctemplebri_SeqFn(GameObject* obj, int p2, ObjSeqState* animUpdate);
int wctemplebri_getExtraSize(void);
int wctemplebri_getObjectTypeId(GameObject* obj);
void wctemplebri_free(void);
void wctemplebri_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemplebri_hitDetect(void);
void wctemplebri_release(void);
void wctemplebri_initialise(void);
void wctemplebri_update(GameObject* obj);
void wctemplebri_init(GameObject* obj, WCTempleBriSetup* setup);

extern ObjectDescriptor gWCTempleBriObjDescriptor;

#endif /* DLLS_OBJECTS_663_WCTEMPLEBRI_H_ */
