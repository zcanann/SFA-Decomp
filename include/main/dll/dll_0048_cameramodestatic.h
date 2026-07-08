#ifndef MAIN_DLL_DLL_0048_CAMERAMODESTATIC_H_
#define MAIN_DLL_DLL_0048_CAMERAMODESTATIC_H_

#include "global.h"

typedef struct CameraModeStaticPlacement
{
    u8 pad0[0x1A - 0x0];
    u8 fovByte;
    u8 flags;
    s16 yaw;
    s16 pitch;
    s16 roll;
    u8 pad22[0x28 - 0x22];
} CameraModeStaticPlacement;

void* fn_80109B04(f32 x, f32 y, f32 z, int filter1, int filter2);
void CameraModeStatic_copyToCurrent(void);
void CameraModeStatic_free(void);
void CameraModeStatic_update(short* camObj);
void CameraModeStatic_init(u8* cam, int p2, int* p3);
void CameraModeStatic_release(void);
void CameraModeStatic_initialise(void);

#endif /* MAIN_DLL_DLL_0048_CAMERAMODESTATIC_H_ */
