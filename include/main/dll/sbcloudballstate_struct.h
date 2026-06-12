#ifndef MAIN_DLL_SBCLOUDBALLSTATE_STRUCT_H_
#define MAIN_DLL_SBCLOUDBALLSTATE_STRUCT_H_

#include "types.h"

typedef struct SBCloudBallState
{
    f32 velX; /* captured from obj+0x24.. on launch */
    f32 velY;
    f32 velZ;
    f32 posX;
    f32 posY;
    f32 posZ;
    int light; /* objCreateLight handle */
    u8 launched;
    u8 pad1D[3];
    f32 fadeTimer; /* nonzero = despawning */
} SBCloudBallState;

#endif
