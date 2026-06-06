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
typedef struct CamCannonState {
    u8 unk0[0x14 - 0x0];
    f32 unk14;
    u8 unk18[0x1C - 0x18];
    f32 unk1C;
    u8 unk20[0x24 - 0x20];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    f32 unk38;
    f32 unk3C;
    u8 unk40[0x44 - 0x40];
    f32 unk44;
    u8 unk48[0x5C - 0x48];
    f32 unk5C;
    f32 unk60;
    u8 unk64[0x68 - 0x64];
} CamCannonState;

#endif /* MAIN_DLL_CAM_CAMCANNON_STATE_H_ */
