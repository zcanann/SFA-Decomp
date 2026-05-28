#include "main/dll/DR/dr_802bbc10_shared.h"

int fn_802BCCFC(void) { return 0x0; }

void DR_EarthWarrior_func21(void) {}

int DR_EarthWarrior_func20(void) { return 0x0; }

int DR_EarthWarrior_func16(void) { return 0x0; }

int DR_EarthWarrior_render2(void) { return 0x0; }

int DR_EarthWarrior_setScale(void) { return 0x0; }

int DR_EarthWarrior_getExtraSize(void) { return 0x14fc; }

int DR_EarthWarrior_getObjectTypeId(void) { return 0x43; }

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_func15(int obj, f32 *x, f32 *y, f32 *z)
{
    *x = *(f32 *)((char *)obj + 0xc);
    *y = *(f32 *)((char *)obj + 0x10);
    *z = *(f32 *)((char *)obj + 0x14);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BDBCC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u16 *)((char *)inner + 0x14e4) |= 0x20;
    return 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_modelMtxFn(int obj, f32 *x, f32 *y, f32 *z)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *x = *(f32 *)((char *)inner + 0x1438);
    *y = *(f32 *)((char *)inner + 0x143c);
    *z = *(f32 *)((char *)inner + 0x1440);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_EarthWarrior_func11(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x14eb) != 0) {
        return 1;
    }
    return 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_EarthWarrior_func14(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x14ea) != 0) {
        return 2;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_func18(int obj, f32 *a, int *b)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *a = (f32)(s32)*(s16 *)((char *)inner + 0x102c);
    *b = *(s16 *)((char *)inner + 0x102e);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_release(void)
{
    if (lbl_803DE4D0 != NULL) {
        Resource_Release((int)lbl_803DE4D0);
        lbl_803DE4D0 = NULL;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BCD04(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    *(u8 *)((char *)obj + 0xaf) |= 8;
    fz = lbl_803E8304;
    *(f32 *)((char *)p2 + 0x294) = fz;
    *(f32 *)((char *)p2 + 0x284) = fz;
    *(f32 *)((char *)p2 + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        if (((ByteFlags *)((char *)inner + 0x14ec))->b80) {
            ObjAnim_SetCurrentMove(obj, 7, fz, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, 8, fz, 0);
        }
        *(f32 *)((char *)p2 + 0x2a0) = GX_F32_256;
    }
    if (*(s8 *)((char *)p2 + 0x346) != 0) {
        if (*(u8 *)((char *)inner + 0x14e6) == 2) {
            *(s16 *)((char *)inner + 0x14e2) -= 1;
            if (*(s16 *)((char *)inner + 0x14e2) <= 0) {
                *(f32 *)((char *)inner + 0x1444) = lbl_803DC76C;
                Camera_EnableViewYOffset();
                CameraShake_SetAllMagnitudes(lbl_803E8338);
                playerAddHealth((int)Obj_GetPlayerObject(), -1);
                *(s16 *)((char *)inner + 0x14e2) = 0;
            }
            return *(int *)((char *)inner + 0x14d8) + 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_initialise(void)
{
    ((void **)lbl_803DB1B0)[0] = (void *)fn_802BDBCC;
    ((void **)lbl_803DB1B0)[1] = (void *)fn_802BD7AC;
    ((void **)lbl_803DB1B0)[2] = (void *)fn_802BCE14;
    ((void **)lbl_803DB1B0)[3] = (void *)fn_802BCD04;
    lbl_803DE4D4 = (void *)fn_802BCCFC;
    if (lbl_803DE4D0 == NULL) {
        lbl_803DE4D0 = (void *)Resource_Acquire(0x5a, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 DR_EarthWarrior_func19(int obj, f32 *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 v = lbl_803E8360 * *(f32 *)((char *)inner + 0x294) + lbl_803E8354;
    if (v < lbl_803E8354) {
        v = lbl_803E8354;
    } else if (v > lbl_803E8364) {
        v = lbl_803E8364;
    }
    *out = -v;
    return lbl_803E8304;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int *)((char *)p1 + 0xb8);
    if (vis == -1) {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E8338);
        ObjPath_GetPointWorldPosition(p1, 0xb, (char *)inner + 0x1438, (char *)inner + 0x143c, (char *)inner + 0x1440, 0);
        ObjPath_GetPointWorldPositionArray(p1, 3, 4, (char *)inner + 0xb18);
    } else if (vis != 0) {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E8338);
        ObjPath_GetPointWorldPosition(p1, 0xb, (char *)inner + 0x1438, (char *)inner + 0x143c, (char *)inner + 0x1440, 0);
        ObjPath_GetPointWorldPositionArray(p1, 3, 4, (char *)inner + 0xb18);
        dll_2E_func06(p1, (char *)inner + 0x3ec, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_free(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(void **)((char *)inner + 0x14f8) != NULL) {
        fn_80026C88(*(int *)((char *)inner + 0x14f8));
    }
    ObjGroup_RemoveObject(obj, 0xa);
    if (((ByteFlags *)((char *)inner + 0x14ec))->b02) {
        (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
    }
    if (*(void **)((char *)inner + 0xb54) != NULL) {
        ObjLink_DetachChild(obj, *(int *)((char *)inner + 0xb54));
        Obj_FreeObject(*(int *)((char *)inner + 0xb54));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_func23(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (mode == 1) {
        *(s16 *)((char *)inner + 0x14e2) += 4;
        objAudioFn_800393f8(obj, (char *)inner + 0x3bc, 0x291, 0x1000, -1, 1);
        *(f32 *)((char *)inner + 0x1444) = lbl_803E82E8;
        *(f32 *)((char *)lbl_8033527C + 0x24) = *(f32 *)((char *)inner + 0x1444);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_func17(int obj, int param)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0x14e6) = (u8)param;
    if (param == 0) {
        GameBit_Set(0x7bc, 0);
        GameBit_Set(0x7d4, 1);
        *(u8 *)((char *)inner + 0x9fd) &= ~1;
        ((ByteFlags *)((char *)inner + 0x14ec))->b02 = 0;
        (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
    } else {
        int inner2 = *(int *)((char *)obj + 0xb8);
        int p = *(int *)((char *)obj + 0x4c);
        ((ByteFlags *)((char *)inner2 + 0x14ec))->b02 = 1;
        (*(void (*)(int, int))(*(int *)(*gGameUIInterface + 0x58)))(*(s16 *)((char *)p + 0x1a), 0x5cf);
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner2 + 0x14e2));
        GameBit_Set(0x7bc, 1);
        GameBit_Set(0x7d4, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_func22(int obj, f32 scale)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 lp0, lp1, lp2;
    int mtx = (int)ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lp0, &lp1, &lp2);
    v.mat[1] = lp0;
    v.mat[2] = lp1;
    v.mat[3] = lp2;
    v.angles[0] = 0;
    v.angles[1] = 0;
    v.angles[2] = 0;
    v.mat[0] = scale / *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 0x4);
    setMatrixFromObjectPos(lbl_803DB170, v.angles);
    mtx44_mult(lbl_803DB170, (void *)mtx, lbl_803DB170);
    fn_8003B950((int)lbl_803DB170);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BDBE8(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int i;
    f32 fz;
    *(u8 *)((char *)obj + 0xaf) |= 8;
    if (dll_2E_func07(obj, p3, (void *)(inner + 0x3ec), 0, 0) != 0) {
        return 1;
    }
    for (i = 0; i < *(u8 *)((char *)p3 + 0x8b); i++) {
        int idx = i + 0x81;
        int v = *(u8 *)((char *)p3 + idx);
        switch (v) {
        case 0xa:
            break;
        case 0xe:
        case 0xf:
            *(u8 *)((char *)inner + 0x9fd) |= 1;
            *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x62) &= ~0x20;
            break;
        case 0x10:
            *(u8 *)((char *)inner + 0x9fd) &= ~1;
            *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x62) |= 0x20;
            break;
        }
    }
    *(int *)((char *)inner + 0xeb8) |= 0x800000;
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, inner + 0x4);
    fz = lbl_803E8304;
    *(f32 *)((char *)inner + 0x294) = fz;
    *(f32 *)((char *)inner + 0x284) = fz;
    *(f32 *)((char *)inner + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802BE6E8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int q;
    int slot;
    Obj_GetPlayerObject();
    q = inner + 0xb58;
    slot = (int)Camera_GetCurrentViewSlot();
    *(u8 *)((char *)inner + 0x354) = 0;
    *(int *)((char *)inner + 0) &= ~0x8000;
    if (*(u8 *)((char *)inner + 0x14e6) == 2) {
        *(f32 *)((char *)inner + 0x290) = (f32)(s8)padGetStickX(0);
        *(f32 *)((char *)inner + 0x28c) = (f32)(s8)padGetStickY(0);
        *(int *)((char *)inner + 0x31c) = getButtonsJustPressed(0);
        *(int *)((char *)inner + 0x318) = getButtonsHeld(0);
        *(s16 *)((char *)inner + 0x330) = *(s16 *)slot;
    } else {
        f32 v = lbl_803E8304;
        *(f32 *)((char *)inner + 0x290) = v;
        *(f32 *)((char *)inner + 0x28c) = v;
        *(int *)((char *)inner + 0x31c) = 0;
        *(int *)((char *)inner + 0x318) = 0;
        *(s16 *)((char *)inner + 0x330) = 0;
    }
    *(int *)((char *)inner + 0) |= 0x1000000;
    fn_802B0EA4(obj, q, inner);
    (*(void (*)(int, int, f32, f32, int, void *))(*(int *)(*gPlayerInterface + 0x8)))(obj, inner, timeDelta, timeDelta, (int)lbl_803DB1B0, &lbl_803DE4D4);
    *(s16 *)((char *)obj + 0x2) = (s16)(*(s16 *)((char *)obj + 0x2) + (*(s16 *)((char *)inner + 0x19c) >> 2));
    *(s16 *)((char *)obj + 0x4) = (s16)(*(s16 *)((char *)obj + 0x4) + (*(s16 *)((char *)inner + 0x19e) >> 2));
    if (((ByteFlags *)((char *)inner + 0x14ec))->b02) {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner + 0x14e2));
    }
    fn_802B1BF8(obj, q, inner, timeDelta);
    fn_802B1B28(obj, timeDelta);
    (*(void (*)(int, int, f32))(*(int *)(*gPathControlInterface + 0x10)))(obj, inner + 0x4, timeDelta);
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x14)))(obj, inner + 0x4);
    (*(void (*)(int, int, f32))(*(int *)(*gPathControlInterface + 0x18)))(obj, inner + 0x4, timeDelta);
    *(s16 *)((char *)obj + 0) = *(s16 *)((char *)q + 0x478);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BC830(int obj, int p2, int p3)
{
    *(int *)((char *)p2 + 0x360) |= 0x1000000;
    *(f32 *)((char *)p3 + 0x2a0) = lbl_803E82EC;
    if (*(f32 *)((char *)obj + 0x98) > GXInit_ClearColor &&
        *(f32 *)((char *)obj + 0x98) < GXInit_BlackColor &&
        *(f32 *)((char *)p3 + 0x294) > *(f32 *)((char *)*(int *)((char *)p2 + 0x400) + 0x1c) - GXInit_WhiteColor &&
        *(f32 *)((char *)p3 + 0x298) > lbl_803E82FC &&
        *(int *)((char *)p2 + 0x488) >= 0x96) {
        ((ByteFlags *)((char *)p2 + 0x3f0))->b40 = 1;
        ((ByteFlags *)((char *)p2 + 0x3f0))->b80 = 0;
        *(u8 *)((char *)p2 + 0x8a6) = *(u8 *)((char *)p2 + 0x8a7);
        *(f32 *)((char *)p3 + 0x2a0) = lbl_803E8300;
        ObjAnim_SetCurrentMove(obj, *(s16 *)((char *)*(int *)((char *)p2 + 0x3f8) + 0x3a), lbl_803E8304, 0);
        ObjAnim_SetCurrentEventStepFrames((struct ObjAnimComponent *)obj, 0x10);
        *(int *)((char *)p2 + 0x858) = *(s16 *)((char *)p2 + 0x484);
        *(f32 *)((char *)p2 + 0x844) = (lbl_803E8308 + (*(f32 *)((char *)*(int *)((char *)p2 + 0x400) + 0x14) + *(f32 *)((char *)p3 + 0x294))) / lbl_803E830C;
        *(s16 *)((char *)p2 + 0x478) = *(s16 *)((char *)p2 + 0x484);
        *(s16 *)((char *)p2 + 0x484) += 0x8000;
        *(f32 *)((char *)p3 + 0x294) = -*(f32 *)((char *)p3 + 0x294);
        *(f32 *)((char *)p3 + 0x280) = -*(f32 *)((char *)p3 + 0x280);
    }
    if (((ByteFlags *)((char *)p2 + 0x3f0))->b80 != 0) {
        f32 lim = *(f32 *)((char *)*(int *)((char *)p2 + 0x400) + 0x10);
        if (*(f32 *)((char *)p3 + 0x294) <= lim && *(f32 *)((char *)p3 + 0x280) <= lim) {
            *(int *)((char *)p2 + 0x494) = *(s16 *)((char *)p2 + 0x484);
            ((ByteFlags *)((char *)p2 + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)p2 + 0x3f0))->b80 = 0;
            return 1;
        }
        *(f32 *)((char *)p2 + 0x408) = lbl_803E8304;
        *(f32 *)((char *)p2 + 0x438) = *(f32 *)((char *)p2 + 0x830);
        *(u16 *)((char *)p2 + 0x8d8) |= 8;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
