#ifndef MAIN_DLL_CC_DLL_0189_CCSHARPCLAWPAD_H_
#define MAIN_DLL_CC_DLL_0189_CCSHARPCLAWPAD_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct SharpClawPadSetup
{
    ObjPlacement base;
    u8 rotX;
    u8 pad19;
    s16 activationGameBit;
} SharpClawPadSetup;

typedef struct SharpClawPadState
{
    f32 helpTimer;
} SharpClawPadState;

typedef struct SharpClawPadParticleArgs
{
    u8 pad00[0xc]; /* 0x00: filled in by objfx_spawnArcedBurst, not written here */
    f32 offset[3]; /* 0x0C: emitter offset x/y/z */
} SharpClawPadParticleArgs;

STATIC_ASSERT(offsetof(SharpClawPadParticleArgs, offset) == 0xC);
STATIC_ASSERT(sizeof(SharpClawPadParticleArgs) == 0x18);
STATIC_ASSERT(offsetof(SharpClawPadSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(SharpClawPadSetup, activationGameBit) == 0x1a);
STATIC_ASSERT(sizeof(SharpClawPadSetup) == 0x1c);
STATIC_ASSERT(sizeof(SharpClawPadState) == 0x04);

int CCSharpclawPad_getExtraSize(void);
void CCSharpclawPad_update(GameObject* obj);
void CCSharpclawPad_init(GameObject* obj, SharpClawPadSetup* setup);

extern ObjectDescriptor gCCSharpclawPadObjDescriptor;

#endif /* MAIN_DLL_CC_DLL_0189_CCSHARPCLAWPAD_H_ */
