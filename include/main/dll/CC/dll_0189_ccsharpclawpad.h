#ifndef MAIN_DLL_CC_DLL_0189_CCSHARPCLAWPAD_H_
#define MAIN_DLL_CC_DLL_0189_CCSHARPCLAWPAD_H_

#include "global.h"
#include "main/game_object.h"

typedef struct SharpClawPadParticleArgs
{
    u8 pad00[0xc]; /* 0x00: filled in by objfx_spawnArcedBurst, not written here */
    f32 offset[3]; /* 0x0C: emitter offset x/y/z */
} SharpClawPadParticleArgs;

STATIC_ASSERT(offsetof(SharpClawPadParticleArgs, offset) == 0xC);
STATIC_ASSERT(sizeof(SharpClawPadParticleArgs) == 0x18);

int CCSharpclawPad_getExtraSize(void);
void CCSharpclawPad_update(GameObject* obj);
void CCSharpclawPad_init(int* obj, int* placement);

#endif /* MAIN_DLL_CC_DLL_0189_CCSHARPCLAWPAD_H_ */
