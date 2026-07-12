#ifndef DOLPHIN_GX_GXLEGACY_H_
#define DOLPHIN_GX_GXLEGACY_H_

#include "types.h"

typedef struct FogColor {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} FogColor;

typedef union PPCWGPipe2 {
    u8 u8;
    u16 u16;
    u32 u32;
    s8 s8;
    s16 s16;
    s32 s32;
    f32 f32;
    f64 f64;
} PPCWGPipe2;

PPCWGPipe2 GXWGFifo : (0xCC008000);

void GXBegin(int prim, int fmt, u16 count);
void GXClearVtxDesc(void);
void GXInvalidateTexAll(void);
void GXLoadPosMtxImm(f32* matrix, s32 slot);
void GXResetWriteGatherPipe(void);
void GXSetCullMode(int mode);
void GXSetFog(int type, f32 startz, f32 endz, f32 nearz, f32 farz, FogColor color);
void GXSetLineWidth(int width, int fmt);
void GXSetMisc(int token, u32 val);
void GXSetPointSize(int size, int fmt);
void GXSetVtxDesc(int attr, int type);

#endif /* DOLPHIN_GX_GXLEGACY_H_ */
