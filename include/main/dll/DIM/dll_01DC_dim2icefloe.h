#ifndef MAIN_DLL_DIM_DLL_01DC_DIM2ICEFLOE_H_
#define MAIN_DLL_DIM_DLL_01DC_DIM2ICEFLOE_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/curve.h"

extern ObjectDescriptor gDIM2IceFloeObjDescriptor;

int dim2icefloe_getExtraSize(void);
int dim2icefloe_getObjectTypeId(void);
void dim2icefloe_free(void);
void dim2icefloe_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void dim2icefloe_hitDetect(void);
void dim2icefloe_update(GameObject* obj);
void dim2icefloe_init(GameObject* obj, int p);
void dim2icefloe_release(void);
void dim2icefloe_initialise(void);

typedef struct Dim2IceFloeState
{
    Curve curve;
    int followedObj;
    int targetId;
    f32 curveStep;
    f32 yawJitter;
    f32 bobRate;
    f32 bobBase;
    s16 bobPhase;
    u8 flags;
    u8 padB7;
    u8 paused;
    u8 finishedFlags;
    u8 padBA[2];
} Dim2IceFloeState;

STATIC_ASSERT(sizeof(Dim2IceFloeState) == 0xBC);
STATIC_ASSERT(offsetof(Dim2IceFloeState, followedObj) == 0x9C);

#endif /* MAIN_DLL_DIM_DLL_01DC_DIM2ICEFLOE_H_ */
