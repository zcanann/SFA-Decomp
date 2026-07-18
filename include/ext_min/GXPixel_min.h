#ifndef EXT_MIN_GXPIXEL_MIN_H_
#define EXT_MIN_GXPIXEL_MIN_H_

#include "types.h"

void GXSetColorUpdate(GXBool update_enable);

void GXSetFieldMode(GXBool field_mode, GXBool half_aspect_ratio);
void GXSetPixelFmt(GXPixelFmt pix_fmt, GXZFmt16 z_fmt);
void GXSetDither(GXBool dither);
void GXSetAlphaUpdate(GXBool update_enable);
#endif /* EXT_MIN_GXPIXEL_MIN_H_ */
