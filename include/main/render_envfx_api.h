#ifndef MAIN_RENDER_ENVFX_API_H_
#define MAIN_RENDER_ENVFX_API_H_

#include "types.h"

#ifdef RENDER_ENVFX_DIRECT_INT_CALL
int getEnvfxActImmediately(int source, int target, u16 index, int flags);
int getEnvfxAct(int source, int target, u16 index, int flags);
#else
struct GameObject;

typedef void (*EnvfxActVoidFn)(void* source, void* target, int index, int flags);
typedef int (*EnvfxActIntFn)(int source, int target, u16 index, int flags);

int getEnvfxActImmediately(struct GameObject* source, struct GameObject* target, u16 index, int flags);
int getEnvfxAct(struct GameObject* source, struct GameObject* target, u16 index, int flags);

#define getEnvfxActVoid(source, target, index, flags)                                                                  \
    (((EnvfxActVoidFn)getEnvfxAct)((void*)(source), (void*)(target), (index), (flags)))
#define getEnvfxActImmediatelyVoid(source, target, index, flags)                                                       \
    (((EnvfxActVoidFn)getEnvfxActImmediately)((void*)(source), (void*)(target), (index), (flags)))
#define getEnvfxActInt(source, target, index, flags)                                                                   \
    (((EnvfxActIntFn)getEnvfxAct)((int)(source), (int)(target), (index), (flags)))
#define getEnvfxActImmediatelyInt(source, target, index, flags)                                                        \
    (((EnvfxActIntFn)getEnvfxActImmediately)((int)(source), (int)(target), (index), (flags)))
#endif

#endif /* MAIN_RENDER_ENVFX_API_H_ */
