#ifndef MAIN_RCP_DOLPHIN_API_H_
#define MAIN_RCP_DOLPHIN_API_H_

#include "types.h"
#include "dolphin/gx/GXStruct.h"
#include "main/rcp_dolphin_state_api.h"
#include "main/texture.h"

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
void* textureAlloc(u16 width, u16 height, int format, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT,
                   u8 minFilter, u8 magFilter);
void* textureLoad(int texId, u8 flag);
void* textureIdxToPtr(int index);
void Rcp_ResetTextureStageState(void);
void Rcp_ApplyTextureStageCounts(void);
void addVertexColorStage(void);
void texRestructRefs(int mode);
void Rcp_DisableBlurFilter(void);
void turnOnBlurFilter(f32 x, f32 y, f32 z, u8 useArea, u8 bigger);
void Rcp_DisableDistortionFilter(void);
void turnOnDistortionFilter(f32* position, f32 angle2, u32* color, f32 angle1);
void Rcp_SetSpiritVisionEnabled(u8 enabled);
void Rcp_SetMonochromeFilterEnabled(u8 enabled);
void Rcp_SetRenderFlags(u32 bits);
void Rcp_ClearRenderFlags(u32 bits);
void Rcp_DisableHeatEffect(void);
void Rcp_EnableHeatEffect(void);
void setMotionBlur(u8 enabled, f32 amount);
void warpToMap(int idx, s8 transType);
void Rcp_ResetRenderState(void);
void addTexLayerStage(Texture* texture, f32 (*texMtx)[4], int mode);
void addTexLayerStageKColor(Texture* texture, f32 (*texMtx)[4], int mode, GXColor* color);
void addTexLayerStageKAlpha(Texture* texture, f32 (*texMtx)[4], int mode, GXColor* color);
void addTexLayerStageSwizzled(Texture* texture, f32 (*texMtx)[4], int mode, GXColor* color, u8 swapSelector,
                              u8 useKColor);
void addVertexColorKAlphaStage(GXColor* color);
void addKColorModulateStage(GXColor* color);
void addColorFadeStage(GXColor* color);

/* Pending warp destination saved by warpToMap from the map-warp tab entry and
 * applied to the player position on map reload (vec3 + a map-layer s16 and a
 * facing-angle s16, each truncated to s8 into the pos map/angle bytes).
 * 16-byte record of WARPTAB.bin (fileId 0x1c). */
typedef struct WarpDestination
{
    f32 x;
    f32 y;
    f32 z;
    s16 layer;
    s16 angle;
} WarpDestination;

extern WarpDestination gRcpPendingWarpDest;

#endif /* MAIN_RCP_DOLPHIN_API_H_ */
