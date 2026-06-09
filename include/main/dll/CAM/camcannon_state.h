#ifndef MAIN_DLL_CAM_CAMCANNON_STATE_H_
#define MAIN_DLL_CAM_CAMCANNON_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * CamCannonState - the heap record behind the .sbss pointer
 * lbl_803DD560, shared by CameraModeTestStrength and the camcannon
 * transition helper. The first four words are test-strength path state;
 * the transition-lerp record starts at 0x10.
 */
/* Transition-lerp record: [start,end] f32 pairs per channel fed to
 * Curve_EvalLinear(elapsed/duration, &pair); starts live in the pad bytes
 * before each named End field (pos pairs at +0x10/18/20). */
typedef struct CamCannonState {
    void *linkedObject;
    int pathTag;
    int prevNodeId;
    int nextNodeId;
    f32 posXStart;
    f32 posXEnd;
    f32 posYStart;
    f32 posYEnd;
    f32 posZStart;
    f32 posZEnd;
    f32 rotXStart;
    f32 rotXEnd;
    f32 rotYStart;
    f32 rotYEnd;
    f32 rotZStart;
    f32 rotZEnd;
    f32 fovStart;
    f32 fovEnd;
    f32 speedCurve[4];
    f32 pathProgress; /* Also used as the fifth transition speed-curve sample. */
    f32 elapsed;
    f32 duration;
    u8 transitionComplete;
    u8 pathFailed;
    u8 pad66[0x68 - 0x66];
} CamCannonState;

STATIC_ASSERT(sizeof(CamCannonState) == 0x68);
STATIC_ASSERT(offsetof(CamCannonState, linkedObject) == 0x00);
STATIC_ASSERT(offsetof(CamCannonState, pathTag) == 0x04);
STATIC_ASSERT(offsetof(CamCannonState, prevNodeId) == 0x08);
STATIC_ASSERT(offsetof(CamCannonState, nextNodeId) == 0x0C);
STATIC_ASSERT(offsetof(CamCannonState, posXStart) == 0x10);
STATIC_ASSERT(offsetof(CamCannonState, rotXStart) == 0x28);
STATIC_ASSERT(offsetof(CamCannonState, fovStart) == 0x40);
STATIC_ASSERT(offsetof(CamCannonState, speedCurve) == 0x48);
STATIC_ASSERT(offsetof(CamCannonState, pathProgress) == 0x58);
STATIC_ASSERT(offsetof(CamCannonState, elapsed) == 0x5C);
STATIC_ASSERT(offsetof(CamCannonState, duration) == 0x60);
STATIC_ASSERT(offsetof(CamCannonState, transitionComplete) == 0x64);
STATIC_ASSERT(offsetof(CamCannonState, pathFailed) == 0x65);

#endif /* MAIN_DLL_CAM_CAMCANNON_STATE_H_ */
