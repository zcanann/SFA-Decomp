#ifndef MAIN_RCP_DOLPHIN_API_H_
#define MAIN_RCP_DOLPHIN_API_H_

#include "types.h"
#include "main/rcp_dolphin_state_api.h"
#include "main/texture.h"

struct _GXColor;

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
void* textureAlloc(u16 width, u16 height, int format, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT,
                   u8 minFilter, u8 magFilter);
void* textureLoad(int texId, u8 flag);
void* textureIdxToPtr(int index);
void resetLotsOfRenderVars(void);
void textureFn_800528bc(void);
void gxColorFn_800523d0(void);
void texRestructRefs(int mode);
void Rcp_DisableBlurFilter(void);
void turnOnBlurFilter(f32 x, f32 y, f32 z, u8 useArea, u8 bigger);
void Rcp_DisableDistortionFilter(void);
void turnOnDistortionFilter(f32* position, f32 angle2, u32* color, f32 angle1);
void Rcp_SetSpiritVisionEnabled(u8 enabled);
void Rcp_SetMonochromeFilterEnabled(u8 enabled);
void Rcp_SetRenderFlags(u32 bits);
void Rcp_ClearRenderFlags(u32 bits);
void timeOfDayFn_80055000(void);
void timeOfDayFn_80055038(void);
void setMotionBlur(u8 enabled, f32 amount);
void warpToMap(int idx, s8 transType);
void textureSetAnimationFrameStep(Texture* texture, u16 frameStep);
void textureSelectAnimationFramePair(void* context, Texture* texture, Texture* forcedTexture, int flags, int packed,
                                     int unused0, int unused1);
void Rcp_ResetRenderState(void);
void textureUpdateAnimationFrame(const Texture* texture, u32* flags, s32* frame);
void fn_80051868(Texture* texture, f32 (*texMtx)[4], int mode);
void fn_80051B00(Texture* texture, f32 (*texMtx)[4], int mode, struct _GXColor* color);
void fn_80051D5C(Texture* texture, f32 (*texMtx)[4], int mode, struct _GXColor* color);
void gxFn_80051fb8(Texture* texture, f32 (*texMtx)[4], int mode, struct _GXColor* color, u8 swapSelector,
                   u8 useKColor);
void textureFn_800524ec(struct _GXColor* color);
void gxColorFn_80052764(struct _GXColor* color);
void gxTextureFn_80052638(struct _GXColor* color);
Texture* textureGetAnimationFrame(Texture* texture, int frame);

#endif /* MAIN_RCP_DOLPHIN_API_H_ */
