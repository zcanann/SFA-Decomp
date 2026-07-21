#ifndef MAIN_DLL_DLL_0184_ANIMSHARPCLAW_H_
#define MAIN_DLL_DLL_0184_ANIMSHARPCLAW_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/objseq.h"

typedef struct AnimsharpclawPlacement
{
    ObjPlacement base;
    s16 animationBank;
    s16 sequenceGameBit;
    u8 pad1C[0x24 - 0x1C];
    u8 positionDamping;
} AnimsharpclawPlacement;

typedef struct AnimsharpclawState
{
    ObjSeqState sequence;
    u8 pad138[0x140 - 0x138];
} AnimsharpclawState;

typedef struct AnimsharpclawChildSetup
{
    ObjPlacement base;
    u8 pad18[0x20 - 0x18];
} AnimsharpclawChildSetup;

STATIC_ASSERT(offsetof(AnimsharpclawPlacement, animationBank) == 0x18);
STATIC_ASSERT(offsetof(AnimsharpclawPlacement, sequenceGameBit) == 0x1A);
STATIC_ASSERT(offsetof(AnimsharpclawPlacement, positionDamping) == 0x24);
STATIC_ASSERT(offsetof(AnimsharpclawState, sequence) == 0x0);
STATIC_ASSERT(sizeof(AnimsharpclawState) == 0x140);
STATIC_ASSERT(sizeof(AnimsharpclawChildSetup) == 0x20);

int animsharpclaw_handleAnimEvents(GameObject* obj, ObjAnimUpdateState* animUpdate);
int animsharpclaw_getExtraSize(void);
int animsharpclaw_getObjectTypeId(void);
void animsharpclaw_free(GameObject* obj);
void animsharpclaw_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void animsharpclaw_hitDetect(void);
void animsharpclaw_update(GameObject* obj);
void animsharpclaw_init(GameObject* obj, AnimsharpclawPlacement* placement);
void animsharpclaw_release(void);
void animsharpclaw_initialise(void);

extern ObjectDescriptor gAnimSharpclawObjDescriptor;

#endif /* MAIN_DLL_DLL_0184_ANIMSHARPCLAW_H_ */
