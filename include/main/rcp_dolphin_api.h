#ifndef MAIN_RCP_DOLPHIN_API_H_
#define MAIN_RCP_DOLPHIN_API_H_

#include "types.h"
#include "main/texture.h"

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
void Rcp_DisableDistortionFilter(void);
void Rcp_SetSpiritVisionEnabled(u8 enabled);
void fn_80053ED0(u32 bits);
void fn_80053EBC(u32 bits);
void timeOfDayFn_80055000(void);
void timeOfDayFn_80055038(void);
void setMotionBlur(u8 enabled, f32 amount);
void warpToMap(int idx, s8 transType);
void fn_800541A4(Texture* texture, s16 frameStep);
void fn_800542F4(void);
void textureAnimFn_80053f2c(const Texture* texture, u32* flags, s32* frame);
void fn_80051868(u8* texture, f32* texMtx, int mode);
void fn_80051B00(u8* texture, f32* texMtx, int mode, int* color);
void fn_80051D5C(u8* texture, f32* texMtx, int mode, int* color);
void gxFn_80051fb8(u8* texture, f32* texMtx, int mode, int* color, u8 swapSelector, u8 useKColor);
void textureFn_800524ec(int* color);
void gxColorFn_80052764(int* color);
int textureCrazyPointerFollowFn_80054c30(int* texture, int frame);

#define fn_80051868Legacy(texture, texMtx, mode) \
    (((void (*)(void*, int, int))fn_80051868)((texture), (texMtx), (mode)))
#define fn_80051B00Legacy(texture, texMtx, mode, color) \
    (((void (*)(void*, int, int, u8*))fn_80051B00)((texture), (texMtx), (mode), (color)))
#define fn_80051D5CIntMtxLegacy(texture, texMtx, mode, color) \
    (((void (*)(void*, int, int, u8*))fn_80051D5C)((texture), (texMtx), (mode), (color)))
#define fn_80051D5CPtrMtxLegacy(texture, texMtx, mode, color) \
    (((void (*)(void*, void*, int, void*))fn_80051D5C)((texture), (texMtx), (mode), (color)))
#define gxFn_80051fb8IntLegacy(texture, texMtx, mode, color, swapSelector, useKColor) \
    (((void (*)(void*, int, int, void*, int, int))gxFn_80051fb8)( \
        (texture), (texMtx), (mode), (color), (swapSelector), (useKColor)))
#define textureFn_800524ecLegacy(color) \
    (((void (*)(u8*))textureFn_800524ec)((color)))
#define gxColorFn_80052764PtrLegacy(color) \
    (((void (*)(void*))gxColorFn_80052764)((color)))
#define textureCrazyPointerFollowLegacy(texture, frame) \
    (((void* (*)(void*, int))textureCrazyPointerFollowFn_80054c30)((texture), (frame)))
#define fn_800541A4Promoted(texture, frameStep) \
    (((void (*)(Texture*, int))fn_800541A4)((texture), (frameStep)))
#define textureLoadIntLegacy(texId, flag) \
    (((int (*)(int, int))textureLoad)((texId), (flag)))

#endif /* MAIN_RCP_DOLPHIN_API_H_ */
