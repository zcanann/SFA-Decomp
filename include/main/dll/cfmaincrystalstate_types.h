#ifndef MAIN_DLL_CFMAINCRYSTALSTATE_TYPES_H_
#define MAIN_DLL_CFMAINCRYSTALSTATE_TYPES_H_

#include "types.h"

typedef struct
{
    f32 startX, endX, startY, endY, startZ, endZ;
    u8 colorR, colorG, colorB, active;
} CrystalBeam;

typedef struct CfMainCrystalState
{
    f32 pylonX[3]; /* per-pylon beam source position */
    f32 crystalX;
    f32 pylonY[3];
    f32 crystalY;
    f32 pylonZ[3];
    f32 crystalZ;
    s16 pylonTimer[3]; /* 0x30: 0 unseen; ramps to 0x78 once reported */
    s16 crystalKnown; /* 0x36 */
    CrystalBeam beams[10]; /* 0x38 */
    s16 charge; /* 0x150: convergence charge frames */
    f32 humVolume; /* 0x154 */
    int unk158;
    u8 chime[4]; /* 0x15c: per-beam chime timers */
} CfMainCrystalState;

#endif
