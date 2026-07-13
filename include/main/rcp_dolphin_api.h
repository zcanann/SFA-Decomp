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

#define fn_800541A4Promoted(texture, frameStep) \
    (((void (*)(Texture*, int))fn_800541A4)((texture), (frameStep)))
#define textureLoadIntLegacy(texId, flag) \
    (((int (*)(int, int))textureLoad)((texId), (flag)))

#endif /* MAIN_RCP_DOLPHIN_API_H_ */
