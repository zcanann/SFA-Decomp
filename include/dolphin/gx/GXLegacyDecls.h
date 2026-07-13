#ifndef DOLPHIN_GX_GXLEGACYDECLS_H_
#define DOLPHIN_GX_GXLEGACYDECLS_H_

#include "types.h"

typedef struct FogColor
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} FogColor;

void GXBegin(int prim, int fmt, u16 count);
void GXClearVtxDesc(void);
void GXInvalidateTexAll(void);
void GXLoadPosMtxImm(f32* matrix, s32 slot);
void GXResetWriteGatherPipe(void);
void GXSetProjection(f32* matrix, s32 projectionMode);
void GXSetViewport(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane);
void GXSetViewportJitter(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane, u32 field);
void GXSetCullMode(int mode);
void GXSetFog(int type, f32 startz, f32 endz, f32 nearz, f32 farz, FogColor color);
void GXSetLineWidth(int width, int fmt);
void GXSetMisc(int token, u32 val);
void GXSetPointSize(int size, int fmt);
void GXSetVtxDesc(int attr, int type);
void GXSetArray(int attr, void* base, int stride);
void GXSetCurrentMtx(u32 id);
void GXSetTevKColorSel(int stage, int sel);
void GXSetTevKAlphaSel(int stage, int sel);
void GXSetNumIndStages(int count);
void GXSetNumTexGens(int count);
void GXSetNumTevStages(int count);
void GXSetNumChans(int count);
void GXSetTevDirect(int stage);
void GXSetTevOrder(int stage, int coord, int map, int color);
void GXSetTevColorIn(int stage, int a, int b, int c, int d);
void GXSetTevAlphaIn(int stage, int a, int b, int c, int d);
void GXSetTevSwapMode(int stage, int ras, int tex);
void GXSetTevColorOp(int stage, int op, int bias, int scale, int clamp, int reg);
void GXSetTevAlphaOp(int stage, int op, int bias, int scale, int clamp, int reg);
void GXSetBlendMode(int type, int src, int dst, int op);
void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
void GXSetTevKColor(int id, void* color);
void GXCallDisplayList(void* list, u32 size);
void GXBeginDisplayList(void* list, u32 size);
u32 GXEndDisplayList(void);

#endif /* DOLPHIN_GX_GXLEGACYDECLS_H_ */
