#ifndef MAIN_DLL_CAM_VIEWFINDER_STATE_H_
#define MAIN_DLL_CAM_VIEWFINDER_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/curve.h"

typedef struct ViewfinderHermiteChannel {
    f32 start;
    f32 end;
    f32 startTangent;
    f32 endTangent;
} ViewfinderHermiteChannel;

typedef struct ViewfinderFlags {
    u8 zoomHudEnabled : 1;
    u8 sfxEnabled : 1;
    u8 zoomSfxPlaying : 1;
    u8 rest : 5;
} ViewfinderFlags;

/*
 * ViewfinderState - the heap record behind the .sbss pointer
 * lbl_803DD548, used by the dll_5B camera modes (CameraModeViewfinder /
 * CameraModeDebug / CameraModeStatic / firstPerson). The five
 * ViewfinderHermiteChannel members are the control-point/tangent arrays
 * fed to Curve_BuildHermiteCoeffs through viewCurve.
 */
typedef struct ViewfinderState {
    u8 unk0[0x4 - 0x0];
    f32 yOffset;
    u8 unk8[0x10 - 0x8];
    ViewfinderHermiteChannel posXCurve;
    ViewfinderHermiteChannel posYCurve;
    ViewfinderHermiteChannel posZCurve;
    ViewfinderHermiteChannel yawCurve;
    ViewfinderHermiteChannel pitchCurve;
    u8 unk60[0x78 - 0x60];
    Curve viewCurve;
    f32 height;
    f32 exitDistance;
    f32 yawSpeed;
    f32 camPosX;
    f32 camPosY;
    f32 camPosZ;
    u8 mode;
    ViewfinderFlags flags;
    u8 unk12E[0x130 - 0x12E];
    f32 clampedPosY;
} ViewfinderState;

STATIC_ASSERT(sizeof(ViewfinderHermiteChannel) == 0x10);
STATIC_ASSERT(offsetof(ViewfinderState, posXCurve) == 0x10);
STATIC_ASSERT(offsetof(ViewfinderState, posYCurve) == 0x20);
STATIC_ASSERT(offsetof(ViewfinderState, posZCurve) == 0x30);
STATIC_ASSERT(offsetof(ViewfinderState, yawCurve) == 0x40);
STATIC_ASSERT(offsetof(ViewfinderState, pitchCurve) == 0x50);
STATIC_ASSERT(offsetof(ViewfinderState, yawSpeed) == 0x11C);
STATIC_ASSERT(offsetof(ViewfinderState, exitDistance) == 0x118);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve) == 0x78);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve.sample) == 0xE0);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve.dir) == 0xF8);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve.px) == 0xFC);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve.count) == 0x108);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve.eval) == 0x10C);
STATIC_ASSERT(offsetof(ViewfinderState, viewCurve.coeffFn) == 0x110);
STATIC_ASSERT(offsetof(ViewfinderState, flags) == 0x12D);

#endif /* MAIN_DLL_CAM_VIEWFINDER_STATE_H_ */
