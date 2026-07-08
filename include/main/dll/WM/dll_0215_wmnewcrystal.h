#ifndef MAIN_DLL_WM_DLL_0215_WMNEWCRYSTAL_H_
#define MAIN_DLL_WM_DLL_0215_WMNEWCRYSTAL_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

typedef struct WmNewCrystalState
{
    u8 fxState[0x34];    /* 0x00: primary glow-effect block (WM_newcrystalFn_800969b0) */
    u8 altFxState[0x34]; /* 0x34: secondary glow-effect block */
    u8 active;           /* 0x68: green crystal still bursting */
    u8 pad69[3];
} WmNewCrystalState;

/* layout-compatible with the PartFxSpawnParams head (effect_interfaces.h) */
typedef struct WmNewCrystalParticleParams
{
    u8 pad0[6];
    s16 pathPoint; /* 0x06 */
    u8 pad8[4];
    f32 x; /* 0x0C */
    f32 y; /* 0x10 */
    f32 z; /* 0x14 */
} WmNewCrystalParticleParams;

STATIC_ASSERT(offsetof(WmNewCrystalState, altFxState) == 0x34);
STATIC_ASSERT(offsetof(WmNewCrystalState, active) == 0x68);
STATIC_ASSERT(sizeof(WmNewCrystalState) == 0x6C);
STATIC_ASSERT(offsetof(WmNewCrystalParticleParams, pathPoint) == 0x06);
STATIC_ASSERT(offsetof(WmNewCrystalParticleParams, x) == 0x0C);
STATIC_ASSERT(sizeof(WmNewCrystalParticleParams) == 0x18);

int WM_newcrystal_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* actor);
int WM_newcrystal_getExtraSize(void);
int WM_newcrystal_getObjectTypeId(void);
void WM_newcrystal_free(void);
void WM_newcrystal_render(int p1, int p2, int p3, int p4, int p5, s8 vis);
void WM_newcrystal_hitDetect(void);
void WM_newcrystal_update(void);
void WM_newcrystal_init(GameObject* obj, void* setup);
void WM_newcrystal_release(void);
void WM_newcrystal_initialise(void);

#endif /* MAIN_DLL_WM_DLL_0215_WMNEWCRYSTAL_H_ */
