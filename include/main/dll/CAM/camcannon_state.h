#ifndef MAIN_DLL_CAM_CAMCANNON_STATE_H_
#define MAIN_DLL_CAM_CAMCANNON_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * CamCannonState - the heap record behind the .sbss pointer
 * lbl_803DD560, used by the camcannon camera mode. Field widths mirror
 * the deref widths observed in camcannon.c; the span covers every
 * observed access - the true allocation may be larger.
 */
/* Transition-lerp record: [start,end] f32 pairs per channel fed to
 * Curve_EvalLinear(elapsed/duration, &pair); starts live in the pad bytes
 * before each named End field (pos pairs at +0x10/18/20). */
typedef struct CamCannonState {
    u8 pad00[0x10 - 0x00];
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
    f32 speedCurve[5];
    f32 elapsed;
    f32 duration;
    u8 transitionComplete;
    u8 pad65[0x68 - 0x65];
} CamCannonState;

STATIC_ASSERT(sizeof(CamCannonState) == 0x68);
STATIC_ASSERT(offsetof(CamCannonState, posXStart) == 0x10);
STATIC_ASSERT(offsetof(CamCannonState, rotXStart) == 0x28);
STATIC_ASSERT(offsetof(CamCannonState, fovStart) == 0x40);
STATIC_ASSERT(offsetof(CamCannonState, speedCurve) == 0x48);
STATIC_ASSERT(offsetof(CamCannonState, elapsed) == 0x5C);
STATIC_ASSERT(offsetof(CamCannonState, duration) == 0x60);
STATIC_ASSERT(offsetof(CamCannonState, transitionComplete) == 0x64);

#endif /* MAIN_DLL_CAM_CAMCANNON_STATE_H_ */
