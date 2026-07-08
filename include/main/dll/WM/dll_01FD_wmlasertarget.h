#ifndef MAIN_DLL_WM_DLL_01FD_WMLASERTARGET_H_
#define MAIN_DLL_WM_DLL_01FD_WMLASERTARGET_H_

#include "ghidra_import.h"
#include "main/obj_placement.h"

typedef struct WmLaserTargetPlacement
{
    ObjPlacement base;
    u8 pad18[2];
    s16 cooldown; /* 0x1A: frames between accepted toggles */
    u8 pad1C[2];
    s16 toggleGameBit; /* 0x1E: the bit the target toggles (also picks
                           the model bank at init) */
    s16 pairedGameBit; /* 0x20: second bit kept in sync */
    u8 pad22[0x28 - 0x22];
} WmLaserTargetPlacement;

STATIC_ASSERT(offsetof(WmLaserTargetPlacement, cooldown) == 0x1A);
STATIC_ASSERT(offsetof(WmLaserTargetPlacement, toggleGameBit) == 0x1E);
STATIC_ASSERT(offsetof(WmLaserTargetPlacement, pairedGameBit) == 0x20);
STATIC_ASSERT(sizeof(WmLaserTargetPlacement) == 0x28);

typedef struct WmLaserTargetState
{
    s16 cooldown;
    u8 toggleQueued;
    u8 pad3;
} WmLaserTargetState;

STATIC_ASSERT(sizeof(WmLaserTargetState) == 0x4);

int WM_LaserTarget_getExtraSize(void);
int WM_LaserTarget_getObjectTypeId(void);
void WM_LaserTarget_free(void);
void WM_LaserTarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_LaserTarget_hitDetect(void);
void WM_LaserTarget_update(int* obj);
void WM_LaserTarget_init(char* obj, s8* def);
void WM_LaserTarget_release(void);
void WM_LaserTarget_initialise(void);

#endif /* MAIN_DLL_WM_DLL_01FD_WMLASERTARGET_H_ */
