#ifndef MAIN_RENDER_H_
#define MAIN_RENDER_H_

#include "types.h"
#include "main/render_envfx_api.h"
#include "main/render_lactions_api.h"

extern int gRenderMode;
extern f32 lbl_803DE544;
extern int lbl_802C18C0[];
extern int lbl_802C1A24[];

void render_copyPackedU64Tail(u64* dst, u32 packed);
void render_copyPackedU64Head(u64* dst, u32 packed);
s16 renderModeSetOrGet(int mode);
int return0xFFFF_80008B6C(void);

#endif /* MAIN_RENDER_H_ */
