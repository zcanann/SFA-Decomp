#ifndef TRACK_INTERSECT_HUD_API_H_
#define TRACK_INTERSECT_HUD_API_H_

#include "types.h"
#include "dolphin/gx/GXStruct.h"
#include "track/intersect_hud_color_api.h"

#ifdef INTERSECT_DRAWTEX_U8
void drawTexture(void* texture, f32 x, f32 y, u8 alpha, int scale);
void drawScaledTexture(void* texture, f32 x, f32 y, u8 alpha, int scale, int width, int height, int flags);
#else
void drawTexture(void* texture, f32 x, f32 y, int alpha, int scale);
void drawScaledTexture(void* texture, f32 x, f32 y, int alpha, int scale, int width, int height, int flags);
#endif
void drawPartialTexture(void* texture, f32 x, f32 y, int alpha, int scale, int width, int height, int u, int v);
void hudDrawRect(int x1, int y1, int x2, int y2, GXColor color);
void drawViewFinderLine(f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4,
                        GXColor* color);
void hudDrawTriangle(f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, u32* color);
void setHudOpacity(u8 opacity);

#endif /* TRACK_INTERSECT_HUD_API_H_ */
