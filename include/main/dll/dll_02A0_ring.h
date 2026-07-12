#ifndef MAIN_DLL_DLL_02A0_RING_H
#define MAIN_DLL_DLL_02A0_RING_H

#include "global.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/obj_placement.h"

typedef struct RingFlags
{
    u8 bit80 : 1;
    u8 bit40 : 1;
    u8 bit20 : 1;
    u8 bit10 : 1;
    u8 pad : 4;
} RingFlags;

typedef struct RingState
{
    u8 mode;
    u8 route;
    u16 linkId;
    f32 pullHeight;
    f32 origX;
    f32 origY;
    f32 arwingYOffset;
    RingFlags flags;
    u8 phase;
    u8 pad16[2];
    f32 pullTimer;
    u8 pad1C[4];
    ModelLightStruct* light;
} RingState;

typedef struct RingPlacement
{
    ObjPlacement base;
    s8 modeFlag;
    u8 route;
    s16 linkId;
    s16 pullHeight;
    u8 pad1E[2];
    s16 activateBit;
} RingPlacement;

typedef struct RingTable
{
    int f0;
    int f4;
    int f8;
    int fc;
    int f10;
    f32 f14;
} RingTable;

STATIC_ASSERT(sizeof(RingFlags) == 0x1);
STATIC_ASSERT(sizeof(RingState) == 0x24);
STATIC_ASSERT(offsetof(RingState, route) == 0x01);
STATIC_ASSERT(offsetof(RingState, linkId) == 0x02);
STATIC_ASSERT(offsetof(RingState, pullHeight) == 0x04);
STATIC_ASSERT(offsetof(RingState, origX) == 0x08);
STATIC_ASSERT(offsetof(RingState, origY) == 0x0C);
STATIC_ASSERT(offsetof(RingState, arwingYOffset) == 0x10);
STATIC_ASSERT(offsetof(RingState, flags) == 0x14);
STATIC_ASSERT(offsetof(RingState, phase) == 0x15);
STATIC_ASSERT(offsetof(RingState, pullTimer) == 0x18);
STATIC_ASSERT(offsetof(RingState, light) == 0x20);
STATIC_ASSERT(offsetof(RingPlacement, modeFlag) == 0x18);
STATIC_ASSERT(offsetof(RingPlacement, route) == 0x19);
STATIC_ASSERT(offsetof(RingPlacement, linkId) == 0x1A);
STATIC_ASSERT(offsetof(RingPlacement, pullHeight) == 0x1C);
STATIC_ASSERT(offsetof(RingPlacement, activateBit) == 0x20);

extern f32 lbl_803E70B0;
extern f32 lbl_803E70B4;
extern f32 lbl_803E70B8;
extern f32 lbl_803E70BC;
extern f32 lbl_803E70C0;
extern f32 lbl_803E70C4;
extern f32 lbl_803E70C8;
extern f32 lbl_803E70CC;
extern f32 lbl_803E70D8;
extern RingTable lbl_8032B720[];

int ring_getExtraSize(void);
int ring_getObjectTypeId(void);
void ring_free(GameObject* obj);
void ring_hitDetect(void);
void ring_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
void ring_release(void);
void ring_initialise(void);
void ring_init(GameObject* obj, RingPlacement* setup);
void ring_update(GameObject* obj);

#endif
