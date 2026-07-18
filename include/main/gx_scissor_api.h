#ifndef MAIN_GX_SCISSOR_API_H_
#define MAIN_GX_SCISSOR_API_H_

#include "types.h"

void GXGetScissor(u32* left, u32* top, u32* width, u32* height);
void GXSetScissor(u32 left, u32 top, u32 width, u32 height);

#endif /* MAIN_GX_SCISSOR_API_H_ */
