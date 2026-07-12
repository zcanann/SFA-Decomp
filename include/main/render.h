#ifndef MAIN_RENDER_H_
#define MAIN_RENDER_H_

#include "types.h"

struct GameObject;

typedef void (*EnvfxActVoidFn)(void* source, void* target, int index, int flags);
typedef int (*EnvfxActIntFn)(int source, int target, u16 index, int flags);
typedef void (*LActionsVoid6Fn)(int source, int target, int index, int arg3, int arg4, int arg5);
typedef int (*LActionsInt6Fn)(int source, int target, u16 index, int arg3, int arg4, int arg5);

extern int gRenderMode;

int getLActions(int source, int target, u16 index);
void render_copyPackedU64Tail(u64* dst, u32 packed);
void render_copyPackedU64Head(u64* dst, u32 packed);
int getEnvfxActImmediately(struct GameObject* source, struct GameObject* target, u16 index, int flags);
int getEnvfxAct(struct GameObject* source, struct GameObject* target, u16 index, int flags);
s16 renderModeSetOrGet(int mode);
int return0xFFFF_80008B6C(void);

#define getEnvfxActVoid(source, target, index, flags) \
    (((EnvfxActVoidFn)getEnvfxAct)((void*)(source), (void*)(target), (index), (flags)))
#define getEnvfxActImmediatelyVoid(source, target, index, flags) \
    (((EnvfxActVoidFn)getEnvfxActImmediately)((void*)(source), (void*)(target), (index), (flags)))
#define getEnvfxActInt(source, target, index, flags) \
    (((EnvfxActIntFn)getEnvfxAct)((int)(source), (int)(target), (index), (flags)))
#define getEnvfxActImmediatelyInt(source, target, index, flags) \
    (((EnvfxActIntFn)getEnvfxActImmediately)((int)(source), (int)(target), (index), (flags)))
#define getLActionsVoid6(source, target, index, arg3, arg4, arg5) \
    (((LActionsVoid6Fn)getLActions)((int)(source), (int)(target), (index), (arg3), (arg4), (arg5)))
#define getLActionsInt6(source, target, index, arg3, arg4, arg5) \
    (((LActionsInt6Fn)getLActions)((int)(source), (int)(target), (index), (arg3), (arg4), (arg5)))

#endif /* MAIN_RENDER_H_ */
