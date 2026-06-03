#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int andross_getExtraSize(void) { return 0xec; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int andross_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_free(int obj)
{
    fn_8006CB24(obj);
    Rcp_DisableDistortionFilter();
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E74DC);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void andross_setPartSignal(int obj, int signal)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    *(u8 *)(state + 0xad) |= signal;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int andross_updateModelAlpha(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 v;
    f32 alpha;
    int model;
    int i;

    *(f32 *)(state + 0x68) = lbl_803E74D4;
    v = *(f32 *)(state + 0x68);
    model = *(int *)Obj_GetActiveModel(obj);
    alpha = lbl_803E74B4 * v;
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(u8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = (int)alpha;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void andross_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int i;
    int model;

    *(f32 *)(state + 0x58) = *(f32 *)(setup + 8);
    *(f32 *)(state + 0x5c) = *(f32 *)(setup + 0xc);
    *(f32 *)(state + 0x60) = *(f32 *)(setup + 0x10);
    *(s16 *)(state + 0x98) = 0;
    *(int *)(state + 0x88) = 0;
    *(int *)(state + 0x8c) = -1;
    *(f32 *)(state + 0x64) = lbl_803E7590;
    *(u8 *)(state + 0xb6) = 5;
    *(int *)(state + 0x7c) = 1;
    *(int *)(state + 0x80) = -1;
    *(s16 *)(state + 0xa0) = -0x8000;
    *(s16 *)obj = -0x8000;
    *(f32 *)(state + 0x6c) = lbl_803E7594;
    *(f32 *)(state + 0xa8) = lbl_803E74D4;
    *(f32 *)(state + 0x74) = lbl_803E7598;
    *(f32 *)(state + 0x78) = lbl_803E7530;
    *(u8 *)(state + 0xbc) = 1;
    ObjHits_SetTargetMask(obj, 4);
    *(void **)(obj + 0xbc) = (void *)andross_updateModelAlpha;
    fn_8006CB50();
    model = *(int *)Obj_GetActiveModel(obj);
    for (i = 0; i < *(u8 *)(model + 0xf8); i++) {
        *(u8 *)(ObjModel_GetRenderOp(model, i) + 0x43) = 0;
    }
    GameBit_Set(0xd, 0);
    unlockLevel(0, 0, 1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void fn_8023A87C(int p1, int p2)
{
    void *spawned;

    spawned = *(void **)(p2 + 0x10);
    if (spawned != NULL) {
        *(f32 *)((char *)spawned + 0x14) -= lbl_803E74D8;
        *(int *)(p2 + 0x90) -= framesThisStep;
        if (*(int *)(p2 + 0x90) < 0) {
            fn_8022F558(*(int *)(p2 + 0x10), 5);
            *(int *)(p2 + 0x90) = 0;
            *(int *)(p2 + 0x10) = 0;
        }
    } else if (*(f32 *)(p2 + 0x6c) >= lbl_803E74D4) {
        *(f32 *)(p2 + 0x6c) -= timeDelta;
        if (*(f32 *)(p2 + 0x6c) < lbl_803E74D4)
            fn_80239DD8(p1, p2);
    } else if ((u32)GameBit_Get(0x12) != 0) {
        *(f32 *)(p2 + 0x6c) = (f32)(u32)randomGetRange(1, 0x14);
        GameBit_Set(0x12, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_8023A6A4(int p1, f32 a, f32 b, f32 c)
{
    f32 val, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    f32 vel[3];

    result = 0;
    dx = *(f32 *)(p1 + 0xc0) - *(f32 *)(*(int *)p1 + 0xc);
    dy = *(f32 *)(p1 + 0xc4) - *(f32 *)(*(int *)p1 + 0x10);
    dz = *(f32 *)(p1 + 0xc8) - *(f32 *)(*(int *)p1 + 0x14);
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > lbl_803DC4C0)
        result = 1;
    val = dist / b;
    if (val < -a)
        val = -a;
    else if (val > a)
        val = a;
    ang = lbl_803E74A0 * (f32)(u32)yaw / lbl_803E74A4;
    *(f32 *)(p1 + 0xd8) = val * fn_80293E80(ang);
    *(f32 *)(p1 + 0xdc) = val * sin(ang);
    fn_8022D48C((int)vel, *(int *)p1);
    *(f32 *)(p1 + 0xd8) -= vel[0] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xdc) -= vel[1] * lbl_803DC4C4;
    *(f32 *)(p1 + 0xe0) = c;
    return result;
}
#pragma scheduling reset
#pragma peephole reset
