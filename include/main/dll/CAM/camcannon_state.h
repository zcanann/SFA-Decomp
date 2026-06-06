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
    u8 unk0[0x14 - 0x0];
    f32 posXEnd;
    u8 unk18[0x1C - 0x18];
    f32 posYEnd;
    u8 unk20[0x24 - 0x20];
    f32 posZEnd;
    f32 rotXStart;
    f32 rotXEnd;
    f32 rotYStart;
    f32 rotYEnd;
    f32 rotZStart;
    f32 rotZEnd;
    u8 unk40[0x44 - 0x40];
    f32 fovEnd;
    u8 unk48[0x5C - 0x48];
    f32 elapsed;
    f32 duration;
    u8 unk64[0x68 - 0x64];
} CamCannonState;

#endif /* MAIN_DLL_CAM_CAMCANNON_STATE_H_ */
