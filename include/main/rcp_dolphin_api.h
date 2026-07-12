#ifndef MAIN_RCP_DOLPHIN_API_H_
#define MAIN_RCP_DOLPHIN_API_H_

#include "types.h"

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
void* textureAlloc(u16 width, u16 height, int format, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT,
                   u8 minFilter, u8 magFilter);

#endif /* MAIN_RCP_DOLPHIN_API_H_ */
