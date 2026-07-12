#ifndef MAIN_DLL_WC_DLL_0297_WCTEMPLEBRI_H_
#define MAIN_DLL_WC_DLL_0297_WCTEMPLEBRI_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WCTempleBriSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[4];
    s16 solvedBit;
    u8 pad20[4];
} WCTempleBriSetup;

typedef struct WCTempleBriState
{
    f32 maxY;
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
STATIC_ASSERT(offsetof(WCTempleBriState, maxY) == 0x00);
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

extern f32 lbl_803E6E70;
extern f32 lbl_803E6E74;
extern f32 lbl_803E6E78;
extern f32 lbl_803E6E7C;
extern f32 lbl_803E6E90;
extern f32 lbl_803E6E94;

void wctemplebri_updateModelWarp(GameObject* obj, WCTempleBriState* state);
int wctemplebri_SeqFn(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate);
int wctemplebri_getExtraSize(void);
int wctemplebri_getObjectTypeId(GameObject* obj);
void wctemplebri_free(void);
void wctemplebri_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemplebri_hitDetect(void);
void wctemplebri_release(void);
void wctemplebri_initialise(void);
void wctemplebri_update(GameObject* obj);
void wctemplebri_init(GameObject* obj, WCTempleBriSetup* setup);

#endif /* MAIN_DLL_WC_DLL_0297_WCTEMPLEBRI_H_ */
