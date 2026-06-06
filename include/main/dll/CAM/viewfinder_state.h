#ifndef MAIN_DLL_CAM_VIEWFINDER_STATE_H_
#define MAIN_DLL_CAM_VIEWFINDER_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * ViewfinderState - the heap record behind the .sbss pointer
 * lbl_803DD548, used by the dll_5B camera modes (CameraModeViewfinder /
 * CameraModeDebug / CameraModeStatic / firstPerson). Field widths mirror
 * the deref widths observed in dll_5B.c; the span covers every observed
 * access - the true allocation may be larger. The b5/b7 bit flags at
 * 0x12D are the existing ViewfinderFlags overlay.
 */
typedef struct ViewfinderState {
    u8 unk0[0x4 - 0x0];
    f32 unk4;
    u8 unk8[0x10 - 0x8];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    f32 unk38;
    f32 unk3C;
    f32 unk40;
    f32 unk44;
    f32 unk48;
    f32 unk4C;
    f32 unk50;
    f32 unk54;
    f32 unk58;
    f32 unk5C;
    u8 unk60[0xE0 - 0x60];
    f32 unkE0;
    f32 unkE4;
    u8 unkE8[0xF8 - 0xE8];
    int curveParam;
    int curvePointsX;
    int curvePointsY;
    int curvePointsZ;
    int curvePointCount;
    int curveEvalFn;
    int curveCoeffsFn;
    f32 unk114;
    u8 unk118[0x11C - 0x118];
    f32 yawSpeed;
    f32 camPosX;
    f32 camPosY;
    f32 camPosZ;
    u8 mode;
    u8 unk12D;
    u8 unk12E[0x130 - 0x12E];
    f32 clampedPosY;
} ViewfinderState;

STATIC_ASSERT(offsetof(ViewfinderState, yawSpeed) == 0x11C);

#endif /* MAIN_DLL_CAM_VIEWFINDER_STATE_H_ */
