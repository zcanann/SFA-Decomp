#include "ghidra_import.h"

extern void *mmAlloc(int size, int heap, int flags);
extern void mm_free(void *ptr);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, s32 param);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern float sin(float x);
extern void Rcp_DisableBlurFilter(void);
extern void memset(void *dst, int val, int size);

extern f32 *lbl_803DD578;
extern f32 *lbl_803DD584;
extern undefined4 **lbl_803DCA50;

extern f32 lbl_803E19B8;
extern f32 lbl_803E19BC;
extern f32 lbl_803E19C0;
extern f32 lbl_803E19C4;
extern f32 lbl_803E19C8;
extern f32 lbl_803E19D0;
extern f32 lbl_803E19D4;
extern f32 lbl_803E19D8;
extern f32 lbl_803E19DC;

#pragma scheduling off
#pragma peephole off
void CameraModeClimb_init(undefined4 param_1, int param_2, s8 *param_3) {
    f32 local_58;
    f32 local_5c;
    f32 local_60;
    f32 local_64;
    f32 local_68;
    undefined4 local_28[8];
    undefined4 local_24[1];
    undefined4 local_20[1];
    undefined4 local_1c[1];
    int iVar2;

    if (lbl_803DD578 == (f32 *)0) {
        lbl_803DD578 = (f32 *)mmAlloc(0x38, 0xf, 0);
    }
    switch (param_2) {
    case 2:
        *(u16 *)((u8 *)lbl_803DD578 + 0x32) = *(u16 *)((u8 *)lbl_803DD578 + 0x30);
        lbl_803DD578[7] = lbl_803DD578[3];
        lbl_803DD578[9] = lbl_803DD578[4];
        lbl_803DD578[5] = lbl_803DD578[0];
        *(s16 *)((u8 *)lbl_803DD578 + 0x34) = (s16)(lbl_803E19B8 * (f32)(s8)param_3[3]);
        lbl_803DD578[8] = (f32)(s8)param_3[5];
        lbl_803DD578[10] = (f32)(s8)param_3[4];
        lbl_803DD578[6] = (f32)(s8)param_3[2];
        *(s16 *)((u8 *)lbl_803DD578 + 0x2c) = (s16)(s8)param_3[1];
        *(s16 *)((u8 *)lbl_803DD578 + 0x2e) = (s16)(s8)param_3[1];
        break;
    case 1:
    default:
        memset(lbl_803DD578, 0, 0x38);
        iVar2 = ((code)((*lbl_803DCA50)[6]))();
        ((code)(*(undefined4 **)((undefined4 *)iVar2)[1])[8])(&local_58, &local_5c, &local_60, &local_64, &local_68);
        ((code)((*lbl_803DCA50)[14]))(
            (f32)*(u16 *)((u8 *)lbl_803DD578 + 0x30),
            param_1, local_28, local_24, local_20, local_1c, 0);
        *(s16 *)((u8 *)lbl_803DD578 + 0x32) = (s16)local_68;
        lbl_803DD578[7] = local_60;
        lbl_803DD578[9] = local_64;
        lbl_803DD578[5] = *(f32 *)local_1c;
        *(s16 *)((u8 *)lbl_803DD578 + 0x34) = 30;
        lbl_803DD578[8] = lbl_803E19BC;
        lbl_803DD578[10] = lbl_803E19C0;
        lbl_803DD578[6] = lbl_803E19C4 * (local_5c + local_58);
        *(s16 *)((u8 *)lbl_803DD578 + 0x2c) = 60;
        *(s16 *)((u8 *)lbl_803DD578 + 0x2e) = 60;
        lbl_803DD578[1] = *(f32 *)local_1c;
        lbl_803DD578[2] = lbl_803E19C8;
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

void CameraModeClimb_release(void) {}
void CameraModeClimb_initialise(void) {}
void fn_8010DAD4(void) {}
void fn_8010DAD8(void) {}
void CameraModeFixed_update(void) {}

#pragma scheduling off
#pragma peephole off
void CameraModeFixed_init(f32 *param_1, undefined4 param_2, f32 *param_3) {
    if (param_3 != (f32 *)0) {
        param_1[6] = param_3[6];
        param_1[7] = param_3[7];
        param_1[8] = param_3[8];
        Obj_TransformWorldPointToLocal(param_3[6], param_3[7], param_3[8],
                     &param_1[3], &param_1[4], &param_1[5],
                     *(s32 *)&param_1[12]);
        *(s16 *)param_1 = *(s16 *)param_3;
        *(s16 *)((u8 *)param_1 + 2) = *(s16 *)((u8 *)param_3 + 2);
        *(s16 *)((u8 *)param_1 + 4) = *(s16 *)((u8 *)param_3 + 4);
        param_1[45] = param_3[45];
    }
}
#pragma peephole reset
#pragma scheduling reset

void CameraModeFixed_release(void) {}
void CameraModeFixed_initialise(void) {}

#pragma scheduling off
#pragma peephole off
void fn_8010DB7C(f32 *param_1, f32 *param_2, f32 *param_3, f32 *param_4) {
    f32 *pfVar2 = lbl_803DD584;
    f32 dx;
    f32 dz;
    f32 dist;
    u16 angle;
    f32 cosVal;
    f32 sinVal;

    dx = param_1[6] - pfVar2[0];
    dz = param_1[8] - pfVar2[2];
    dist = sqrtf(dz * dz + dx * dx);
    angle = (u16)getAngle(dx, dz);

    {
        f32 scale = lbl_803DD584[17];
        dx *= scale;
        dz *= scale;
    }
    dx += pfVar2[0];
    dz += pfVar2[2];

    cosVal = fn_80293E80(lbl_803E19D0 * (f32)(s32)((angle & 0xFFFF) + *(s32 *)&lbl_803DD584[6]) / lbl_803E19D4);
    sinVal = sin(lbl_803E19D0 * (f32)(s32)((angle & 0xFFFF) + *(s32 *)&lbl_803DD584[6]) / lbl_803E19D4);

    if (dist < lbl_803DD584[16]) {
        dist = lbl_803DD584[16];
    }
    dist += lbl_803DD584[4];

    *param_2 = cosVal * dist + dx;
    *param_3 = (param_1[7] + lbl_803DD584[12]) - lbl_803E19D8 * ((lbl_803E19DC + param_1[7]) - pfVar2[1]);
    *param_4 = sinVal * dist + dz;
}
#pragma peephole reset
#pragma scheduling reset

void fn_8010DD24(void) {}

void fn_8010DD28(void) {
    mm_free(lbl_803DD584);
    lbl_803DD584 = 0;
    Rcp_DisableBlurFilter();
}
