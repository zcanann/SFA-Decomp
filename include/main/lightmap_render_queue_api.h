#ifndef MAIN_LIGHTMAP_RENDER_QUEUE_API_H_
#define MAIN_LIGHTMAP_RENDER_QUEUE_API_H_

#include "global.h"

void lightmap_queueExternalRenderEntry(u32 slotPoolBase, u32 poolIndex, f32* position);
void fn_8005D3B4(u8* object, u8* model, s32 selector);

#endif /* MAIN_LIGHTMAP_RENDER_QUEUE_API_H_ */
