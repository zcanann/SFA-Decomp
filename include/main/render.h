#ifndef MAIN_RENDER_H_
#define MAIN_RENDER_H_

#include "types.h"
#include "main/render_envfx_api.h"

typedef void (*LActionsVoid6Fn)(int source, int target, int index, int arg3, int arg4, int arg5);
typedef int (*LActionsInt6Fn)(int source, int target, u16 index, int arg3, int arg4, int arg5);

extern int gRenderMode;
extern f32 lbl_803DE544;
extern int lbl_802C18C0[];
extern int lbl_802C1A24[];

int getLActions(int source, int target, u16 index);
void render_copyPackedU64Tail(u64* dst, u32 packed);
void render_copyPackedU64Head(u64* dst, u32 packed);
s16 renderModeSetOrGet(int mode);
int return0xFFFF_80008B6C(void);

#define getLActionsVoid6(source, target, index, arg3, arg4, arg5) \
    (((LActionsVoid6Fn)getLActions)((int)(source), (int)(target), (index), (arg3), (arg4), (arg5)))
#define getLActionsInt6(source, target, index, arg3, arg4, arg5) \
    (((LActionsInt6Fn)getLActions)((int)(source), (int)(target), (index), (arg3), (arg4), (arg5)))

#endif /* MAIN_RENDER_H_ */
