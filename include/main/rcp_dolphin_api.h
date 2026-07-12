#ifndef MAIN_RCP_DOLPHIN_API_H_
#define MAIN_RCP_DOLPHIN_API_H_

#include "types.h"
#include "main/texture.h"

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
void* textureAlloc(u16 width, u16 height, int format, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT,
                   u8 minFilter, u8 magFilter);
void Rcp_DisableDistortionFilter(void);
void fn_800541A4(Texture* texture, s16 frameStep);
void textureAnimFn_80053f2c(const Texture* texture, u32* flags, s32* frame);

#define fn_800541A4Promoted(texture, frameStep) \
    (((void (*)(Texture*, int))fn_800541A4)((texture), (frameStep)))

#endif /* MAIN_RCP_DOLPHIN_API_H_ */
