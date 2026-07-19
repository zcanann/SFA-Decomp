#ifndef TRACK_INTERSECT_HUD_API_H_
#define TRACK_INTERSECT_HUD_API_H_

#include "types.h"
#include "dolphin/gx/GXStruct.h"

void drawTexture(void* texture, f32 x, f32 y, int alpha, int scale);
void drawScaledTexture(void* texture, f32 x, f32 y, int alpha, int scale, int width, int height, int flags);
void drawPartialTexture(void* texture, f32 x, f32 y, int alpha, int scale, int width, int height, int u, int v);
void hudDrawColored(int texture, int x, int y, u32* color, int scale, int flags);
void hudDrawRect(int x1, int y1, int x2, int y2, GXColor color);
void setHudOpacity(u8 opacity);

#endif /* TRACK_INTERSECT_HUD_API_H_ */
