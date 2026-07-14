#ifndef TRACK_INTERSECT_HUD_API_H_
#define TRACK_INTERSECT_HUD_API_H_

#include "types.h"

struct Texture;
struct _GXColor;

void hudDrawColored(struct Texture* texture, int x, int y, struct _GXColor* color, u16 scale, u8 flags);

/* Preserve the untyped texture-handle view used by older callers. */
#define hudDrawColoredLegacy(texture, x, y, color, scale, flags)                                                         \
    ((void (*)(int, int, int, void*, int, int))hudDrawColored)((texture), (x), (y), (color), (scale), (flags))

#endif /* TRACK_INTERSECT_HUD_API_H_ */
