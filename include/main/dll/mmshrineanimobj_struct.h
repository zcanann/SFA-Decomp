#ifndef MAIN_DLL_MMSHRINEANIMOBJ_STRUCT_H_
#define MAIN_DLL_MMSHRINEANIMOBJ_STRUCT_H_

#include "types.h"

/* MmShrineAnimObj.flags bits */
#define MMSHRINE_FLAG_POSE_LOCKED 0x4000 /* hold shrine in fixed pose (yaw 0, posY from config), skip normal update */

typedef struct MmShrineAnimObj
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 flags;
    u8 pad08[0x8];
    f32 posY;
    u8 pad14[0x4];
    f32 posX;
    u8 pad1C[0x4];
    f32 posZ;
    u8 pad24[0x12];
    u8 fadeAlpha;
    u8 pad37[0x15];
    u8* config;
    u8 pad50[0x68];
    u8* state;
} MmShrineAnimObj;

#endif
