#include "main/dll/DR/dr_802bbc10_shared.h"

typedef struct {
    s16 v[5];
} EWPathRange;

typedef struct {
    f32 m[4][4];
} EWColorTbl;

extern f32 lbl_803E8310;
extern f32 lbl_803E8314;
extern f32 lbl_803E8318;
extern f32 lbl_803E831C;
extern f32 lbl_803E8320;
extern f32 lbl_803E8324;
extern f32 lbl_803E8328;
extern f32 lbl_803E832C;
extern f32 lbl_803E8330;
extern f32 lbl_803E8334;
extern f32 lbl_803E833C;
extern f32 lbl_803E8340;
extern f32 lbl_803E8344;
extern f32 lbl_803E8348;
extern f32 lbl_803E834C;
extern f32 lbl_803E8350;
extern f32 lbl_803E8358;
extern f32 lbl_803E835C;
extern f32 lbl_803E8368;
extern f32 lbl_803E836C;
extern f32 lbl_803E8370;
extern f32 lbl_803E8374;
extern f32 lbl_803E8378;
extern f32 lbl_803E837C;
extern f32 lbl_803E8380;
extern f32 lbl_803E8384;
extern f32 lbl_803E8388;
extern f32 lbl_803E838C;
extern f32 lbl_803E8394;
extern f32 lbl_803E82F0;
extern f32 GXIndTexMtxScale1024;
extern f32 oneOverTimeDelta;
extern int lbl_803E82D8;
extern u8 lbl_803351F8[];
extern u8 lbl_803352AC[];
extern EWPathRange lbl_802C2CA8;
extern EWPathRange lbl_802C2CB4;
extern EWColorTbl lbl_802C2CC0;
extern char lbl_803DC768;

extern void setAButtonIcon(int icon);
extern void dll_2E_func09(int p, void *a, void *b, int c);
extern void fn_80113F94(int p, f32 f);
extern void objAudioFn_8006edcc(int obj, int a, int b, int c, int d, f32 v, f32 lim);
extern int allocModelStruct2(char *tag, int n);
extern void tailFn_80026c38(int h, f32 a, f32 b, f32 c);
extern void fn_80026C30(int h, int n);
extern void fn_80026C54(int h);
extern int objGetFlagsE5_2(int obj);
extern void Obj_SpawnHitLightAndFade(int obj, void *pos, f32 v);
extern void doRumble(f32 v);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern void storeZeroToFloatParam(int p);
extern void s16toFloat(int p, int v);
extern void fn_802BC788(void);
extern s16 *objModelGetVecFn_800395d8(int obj, int idx);
extern void characterDoEyeAnims(int obj, int p);

void fn_802BCA10(int obj, int q, int p2);

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
void fn_802BE6E8(int obj, int t, int p3)
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

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void fn_802BCA10(int obj, int q, int p2)
{
    s16 *vec0;
    s16 *vec9;
    int v;
    int d;
    v = *(int *)((char *)q + 0x480) << 1;
    if (v < -0x41) {
        d = -0x41;
    } else if (v > 0x41) {
        d = 0x41;
    } else {
        d = v;
    }
    d = d * 0xb6 - (u16)*(s16 *)((char *)q + 0x4d4);
    if (d > 0x8000) {
        d -= 0xffff;
    }
    if (d < -0x8000) {
        d += 0xffff;
    }
    d = (int)((f32)d * lbl_803E8324);
    if (d < -0x16c) {
        d = -0x16c;
    } else if (d > 0x16c) {
        d = 0x16c;
    }
    *(s16 *)((char *)q + 0x4d4) = (f32)d * timeDelta + (f32)(s32)*(s16 *)((char *)q + 0x4d4);
    *(s16 *)((char *)q + 0x4d2) = *(s16 *)((char *)q + 0x4d4) / 2;
    {
        f32 ph = (f32)(s32)*(s16 *)((char *)p2 + 0x19c) / lbl_803E8328;
        f32 t;
        if (ph < lbl_803E8334) {
            t = lbl_803E8334;
        } else if (ph > lbl_803E8338) {
            t = lbl_803E8338;
        } else {
            t = ph;
        }
        d = (int)(lbl_803E832C * (lbl_803E8330 * -t)) - (u16)*(s16 *)((char *)q + 0x4d6);
    }
    if (d > 0x8000) {
        d -= 0xffff;
    }
    if (d < -0x8000) {
        d += 0xffff;
    }
    *(s16 *)((char *)q + 0x4d6) += d;
    vec0 = objModelGetVecFn_800395d8(obj, 0);
    vec9 = objModelGetVecFn_800395d8(obj, 9);
    objModelGetVecFn_800395d8(obj, 4);
    objModelGetVecFn_800395d8(obj, 5);
    if (vec0 != NULL) {
        s16 sv;
        vec0[0] = -*(s16 *)((char *)q + 0x4d6);
        vec0[1] = *(s16 *)((char *)q + 0x4d4) / 2;
        sv = vec0[1];
        if (sv < -4000) {
            sv = -4000;
        } else if (sv > 4000) {
            sv = 4000;
        }
        vec0[1] = sv;
        vec0[2] = 0;
    }
    if (vec9 != NULL) {
        s16 sv;
        int t;
        vec9[1] = *(s16 *)((char *)q + 0x4d2);
        sv = vec9[1];
        if (sv < -3000) {
            sv = -3000;
        } else if (sv > 3000) {
            sv = 3000;
        }
        vec9[1] = sv;
        t = *(s16 *)((char *)q + 0x4d2);
        if (t < 0) {
            t = -t;
        }
        vec9[0] = (s16)(t >> 1);
    }
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BCE14(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int q = inner + 0xb58;
    ((ByteFlags *)((char *)q + 0x3f1))->b04 = 0;
    ((ByteFlags *)((char *)q + 0x3f1))->b08 = 0;
    ((ByteFlags *)((char *)q + 0x3f2))->b10 = 0;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        ((ByteFlags *)((char *)q + 0x3f0))->b80 = 0;
        ((ByteFlags *)((char *)q + 0x3f0))->b40 = 0;
        *(u8 *)((char *)q + 0x8cc) = 0;
        ((ByteFlags *)((char *)q + 0x3f2))->b10 = 1;
    }
    if (!((ByteFlags *)((char *)q + 0x3f0))->b80 && !((ByteFlags *)((char *)q + 0x3f0))->b40 &&
        !((ByteFlags *)((char *)inner + 0x14ec))->b01 && (*(int *)((char *)p2 + 0x31c) & 0x100)) {
        buttonDisable(0, 0x100);
        ((ByteFlags *)((char *)inner + 0x14ec))->b01 = 1;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x70) = 0;
        ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E8304, 0);
        *(u8 *)((char *)p2 + 0x346) = 0;
        Sfx_PlayFromObject(obj, 0x121);
    }
    *(int *)p2 |= 0x800000;
    *(s16 *)((char *)p2 + 0x278) = 0;
    *(f32 *)((char *)q + 0x404) = lbl_803E82E8;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        *(s16 *)((char *)q + 0x484) += *(int *)((char *)q + 0x48c) * 0xb6;
        *(int *)((char *)q + 0x488) = 0;
        *(int *)((char *)q + 0x48c) = 0;
    }
    {
        f32 ph = (*(f32 *)((char *)p2 + 0x298) - lbl_803E8308) / lbl_803E82FC;
        f32 a = *(f32 *)((char *)q + 0x404) - lbl_803E833C;
        f32 t = lbl_803E8304;
        if ((lbl_803E8304 <= ph) && (t = ph, lbl_803E8338 < ph)) {
            t = lbl_803E8338;
        }
        *(f32 *)((char *)q + 0x408) = a * (t * *(f32 *)((char *)q + 0x840));
    }
    if (((ByteFlags *)((char *)q + 0x3f0))->b40) {
        s16 sv;
        *(int *)((char *)q + 0x360) |= 0x1000000;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8300;
        sv = (s16)(int)(lbl_803E8320 * *(f32 *)((char *)obj + 0x98) + (f32)(s32)*(int *)((char *)q + 0x858));
        *(s16 *)((char *)q + 0x478) = sv;
        *(int *)((char *)q + 0x494) = sv;
        if (*(s8 *)((char *)p2 + 0x346) != 0) {
            s16 sw;
            ((ByteFlags *)((char *)q + 0x3f0))->b40 = 0;
            sw = *(s16 *)((char *)q + 0x484);
            *(s16 *)((char *)q + 0x478) = sw;
            *(int *)((char *)q + 0x494) = sw;
            *(u8 *)((char *)q + 0x8cc) = 0xc;
            ((ByteFlags *)((char *)q + 0x3f1))->b04 = 1;
            ((ByteFlags *)((char *)q + 0x3f1))->b08 = 1;
        }
        *(f32 *)((char *)p2 + 0x294) = *(f32 *)((char *)q + 0x844) * timeDelta + *(f32 *)((char *)p2 + 0x294);
        *(f32 *)((char *)q + 0x408) = lbl_803E8304;
        if (*(f32 *)((char *)obj + 0x98) > GXInit_ClearColor && *(f32 *)((char *)obj + 0x98) < lbl_803E8318) {
            *(u16 *)((char *)q + 0x8d8) |= 8;
        }
    } else if (((ByteFlags *)((char *)q + 0x3f0))->b80) {
        if (fn_802BC830(obj, q, p2) != 0) {
            return 2;
        }
    } else if (((ByteFlags *)((char *)inner + 0x14ec))->b01) {
        *(f32 *)((char *)p2 + 0x2a0) = GX_F32_256;
        if (*(s8 *)((char *)p2 + 0x346) != 0) {
            ((ByteFlags *)((char *)inner + 0x14ec))->b01 = 0;
            ((ByteFlags *)((char *)q + 0x3f1))->b08 = 1;
            *(u8 *)(*(int *)((char *)obj + 0x54) + 0x70) = 0;
        }
        {
            f32 m1 = lbl_803E8314;
            f32 m2;
            *(f32 *)((char *)q + 0x428) *= m1;
            m2 = lbl_803E8318;
            *(f32 *)((char *)q + 0x42c) *= m2;
            *(f32 *)((char *)q + 0x430) *= m1;
            *(f32 *)((char *)q + 0x434) *= m2;
        }
        *(f32 *)((char *)q + 0x408) *= lbl_803E831C;
        {
            f32 lim = *(f32 *)(*(int *)((char *)q + 0x400) + 0xc);
            if (*(f32 *)((char *)q + 0x408) < lim) {
                *(f32 *)((char *)q + 0x408) = lim;
            }
        }
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0x15;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 2;
    }
    if (!((ByteFlags *)((char *)inner + 0x14ec))->b01 && !((ByteFlags *)((char *)q + 0x3f0))->b40 &&
        !((ByteFlags *)((char *)q + 0x3f0))->b80 &&
        *(f32 *)((char *)p2 + 0x294) > lbl_803E8340 + *(f32 *)(*(int *)((char *)q + 0x400) + 0x14) &&
        (*(f32 *)((char *)q + 0x470) < lbl_803E8344 || *(int *)((char *)q + 0x488) >= 0x96)) {
        ((ByteFlags *)((char *)q + 0x3f0))->b80 = 1;
        *(int *)((char *)q + 0x360) |= 0x1000000;
        *(f32 *)((char *)q + 0x844) = *(f32 *)((char *)p2 + 0x280);
        ObjAnim_SetCurrentMove(obj, *(s16 *)(*(int *)((char *)q + 0x3f8) + 0x3c), lbl_803E8304, 0);
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E82EC;
    }
    if (!((ByteFlags *)((char *)q + 0x3f0))->b80 && !((ByteFlags *)((char *)q + 0x3f0))->b40) {
        if (*(int *)((char *)q + 0x488) < 0x96) {
            f32 v = interpolate((f32)(s32)*(int *)((char *)q + 0x47c), lbl_803E8338 / *(f32 *)((char *)q + 0x428), timeDelta);
            f32 cap = timeDelta * (*(f32 *)((char *)q + 0x42c) * *(f32 *)((char *)q + 0x420));
            if (v > cap) {
                v = cap;
            }
            if (*(int *)((char *)q + 0x480) < 0) {
                v = -v;
            }
            *(s16 *)((char *)q + 0x478) = (s16)(int)(lbl_803E8348 * v + (f32)(s32)*(s16 *)((char *)q + 0x478));
        }
        if (*(int *)((char *)q + 0x488) < 0x96) {
            f32 v = interpolate((f32)(s32)*(int *)((char *)q + 0x488), lbl_803E8338 / *(f32 *)((char *)q + 0x430), timeDelta);
            f32 cap = *(f32 *)((char *)q + 0x434) * timeDelta;
            if (v > cap) {
                v = cap;
            }
            if (*(int *)((char *)q + 0x48c) < 0) {
                v = -v;
            }
            *(s16 *)((char *)q + 0x484) = (s16)(int)(lbl_803E8348 * v + (f32)(s32)*(s16 *)((char *)q + 0x484));
        } else if (*(f32 *)((char *)p2 + 0x294) <= *(f32 *)(*(int *)((char *)q + 0x400) + 0x4) &&
                   *(f32 *)((char *)p2 + 0x280) <= *(f32 *)(*(int *)((char *)q + 0x400) + 0xc)) {
            *(s16 *)((char *)q + 0x484) += *(int *)((char *)q + 0x48c) * 0xb6;
        }
    }
    if (!((ByteFlags *)((char *)q + 0x3f0))->b40 && !((ByteFlags *)((char *)q + 0x3f1))->b04) {
        f32 v = interpolate(*(f32 *)((char *)q + 0x408) - *(f32 *)((char *)p2 + 0x294), *(f32 *)((char *)q + 0x438), timeDelta);
        f32 r = lbl_803E834C * timeDelta;
        if ((lbl_803E834C * timeDelta <= v) && (r = v, GXInit_ClearColor * timeDelta < v)) {
            r = GXInit_ClearColor * timeDelta;
        }
        if (*(int *)((char *)q + 0x488) >= 0x96 && r > lbl_803E8304) {
            r = lbl_803E8314 * -r;
        }
        *(f32 *)((char *)p2 + 0x294) += r;
        {
            f32 vv = *(f32 *)((char *)p2 + 0x294);
            f32 t = **(f32 **)((char *)q + 0x400);
            if ((t <= vv) && (t = vv, *(f32 *)((char *)q + 0x404) < vv)) {
                t = *(f32 *)((char *)q + 0x404);
            }
            *(f32 *)((char *)p2 + 0x294) = t;
        }
        *(f32 *)((char *)p2 + 0x284) = lbl_803E8304;
    } else {
        f32 vv = *(f32 *)((char *)p2 + 0x294);
        f32 h = *(f32 *)((char *)q + 0x404);
        f32 t = -h;
        if ((-h <= vv) && (t = vv, h < vv)) {
            t = h;
        }
        *(f32 *)((char *)p2 + 0x294) = t;
    }
    *(f32 *)((char *)p2 + 0x280) += interpolate(*(f32 *)((char *)p2 + 0x294) - *(f32 *)((char *)p2 + 0x280), *(f32 *)((char *)q + 0x82c), timeDelta);
    if (!((ByteFlags *)((char *)q + 0x3f0))->b80 && !((ByteFlags *)((char *)q + 0x3f0))->b40 &&
        !((ByteFlags *)((char *)inner + 0x14ec))->b01) {
        int skip = 0;
        f32 blend;
        int i2;
        if (((ByteFlags *)((char *)q + 0x3f1))->b08) {
            skip = 1;
            blend = lbl_803E8304;
        } else {
            blend = *(f32 *)((char *)obj + 0x98);
        }
        i2 = (*(s8 *)((char *)q + 0x8cc) / 4) << 1;
        *(u8 *)((char *)q + 0x8b0) = (i2 >> 1) + 1;
        if (*(u8 *)((char *)q + 0x8b0) > 4) {
            *(u8 *)((char *)q + 0x8b0) = 4;
        }
        if (*(u8 *)((char *)q + 0x8b0) > 3) {
            *(u8 *)((char *)q + 0x8a6) = 0xa;
        } else {
            *(u8 *)((char *)q + 0x8a6) = 8;
        }
        {
            f32 v294 = *(f32 *)((char *)p2 + 0x294);
            int tbl = *(int *)((char *)q + 0x400);
            if (v294 < *(f32 *)(tbl + i2 * 4)) {
                if (*(s8 *)((char *)q + 0x8cc) == 4) {
                    if (*(f32 *)((char *)p2 + 0x280) < *(f32 *)(tbl + 0x10) && *(f32 *)((char *)p2 + 0x298) < lbl_803E8308) {
                        return 2;
                    }
                } else {
                    *(s8 *)((char *)q + 0x8cc) -= 4;
                }
            } else if (v294 >= *(f32 *)(tbl + i2 * 4 + 4)) {
                if (*(s8 *)((char *)q + 0x8cc) < 0x14) {
                    if (*(s8 *)((char *)q + 0x8cc) == 0) {
                        blend = lbl_803E8350;
                    }
                    if (v294 < *(f32 *)((char *)q + 0x404)) {
                        *(u8 *)((char *)q + 0x8cc) += 4;
                    }
                }
            }
        }
        if ((skip != 0 || *(int *)((char *)q + 0x3fc) != *(int *)((char *)q + 0x3f8) ||
             *(s16 *)((char *)obj + 0xa0) != *(s16 *)(*(int *)((char *)q + 0x3f8) + *(s8 *)((char *)q + 0x8cc) * 2)) &&
            (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent *)obj) == 0 || ((ByteFlags *)((char *)q + 0x3f2))->b10 != 0)) {
            if (*(s16 *)((char *)obj + 0xa0) == 0x14) {
                blend = lbl_803E8350;
            }
            ObjAnim_SetCurrentMove(obj, *(s16 *)(*(int *)((char *)q + 0x3f8) + *(s8 *)((char *)q + 0x8cc) * 2), blend, 0);
        }
    }
    if (!((ByteFlags *)((char *)q + 0x3f0))->b80 && !((ByteFlags *)((char *)q + 0x3f0))->b40 &&
        !((ByteFlags *)((char *)inner + 0x14ec))->b01) {
        if (ObjAnim_SampleRootCurvePhase(*(f32 *)((char *)p2 + 0x294), (ObjAnimComponent *)obj, (f32 *)((char *)p2 + 0x2a0)) == 0) {
            *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8354;
        }
    }
    fn_802BCA10(obj, q, p2);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BD7AC(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int q = inner + 0xb58;
    int s;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        *(f32 *)((char *)p2 + 0x294) = lbl_803E8304;
    }
    *(f32 *)((char *)p2 + 0x280) -= interpolate(*(f32 *)((char *)p2 + 0x280), *(f32 *)((char *)q + 0x82c), timeDelta);
    if (*(f32 *)((char *)p2 + 0x280) <= *(f32 *)((char *)lbl_8033527C + 0x8)) {
        *(f32 *)((char *)p2 + 0x280) = lbl_803E8304;
    }
    {
        f32 z = lbl_803E8304;
        *(f32 *)((char *)p2 + 0x284) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    if (!((ByteFlags *)((char *)q + 0x3f0))->b80 && !((ByteFlags *)((char *)q + 0x3f0))->b40 &&
        !((ByteFlags *)((char *)inner + 0x14ec))->b01 && (*(int *)((char *)p2 + 0x31c) & 0x100)) {
        buttonDisable(0, 0x100);
        ((ByteFlags *)((char *)inner + 0x14ec))->b01 = 1;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x70) = 0;
        ObjAnim_SetCurrentMove(obj, 0x14, lbl_803E8304, 0);
        *(u8 *)((char *)p2 + 0x346) = 0;
        return 3;
    }
    if (*(f32 *)((char *)p2 + 0x29c) >= lbl_803E8358 && *(f32 *)((char *)p2 + 0x298) >= lbl_803E8358 &&
        *(f32 *)((char *)p2 + 0x294) >= *(f32 *)(*(int *)((char *)q + 0x400) + 0x4)) {
        return 3;
    }
    s = *(s16 *)*(int *)((char *)q + 0x3f8);
    *(s16 *)((char *)p2 + 0x278) = 0;
    *(f32 *)((char *)q + 0x404) = lbl_803E82E8;
    {
        f32 ph = (*(f32 *)((char *)p2 + 0x298) - lbl_803E8308) / lbl_803E82FC;
        f32 a = *(f32 *)((char *)q + 0x404) - lbl_803E833C;
        f32 t = lbl_803E8304;
        if ((lbl_803E8304 <= ph) && (t = ph, lbl_803E8338 < ph)) {
            t = lbl_803E8338;
        }
        *(f32 *)((char *)q + 0x408) = a * (t * *(f32 *)((char *)q + 0x840));
    }
    *(f32 *)((char *)p2 + 0x294) += interpolate(*(f32 *)((char *)q + 0x408) - *(f32 *)((char *)p2 + 0x294), *(f32 *)((char *)q + 0x438), timeDelta);
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        *(int *)((char *)q + 0x47c) = 0;
        *(int *)((char *)q + 0x480) = 0;
        *(int *)((char *)q + 0x488) = 0;
        *(int *)((char *)q + 0x48c) = 0;
        *(u8 *)((char *)q + 0x8a6) = 8;
        *(u8 *)((char *)q + 0x8b0) = 0;
        *(f32 *)((char *)p2 + 0x2b8) = lbl_803E835C;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8354;
    }
    if (*(s16 *)((char *)obj + 0xa0) == *(s16 *)(*(int *)((char *)q + 0x3f8) + 0x30) ||
        *(s16 *)((char *)obj + 0xa0) == *(s16 *)(*(int *)((char *)q + 0x3f8) + 0x32)) {
        if (*(s8 *)((char *)p2 + 0x346) != 0 && ObjAnim_GetCurrentEventCountdown((ObjAnimComponent *)obj) == 0 &&
            !((ByteFlags *)((char *)inner + 0x14ec))->b01) {
            ObjAnim_SetCurrentMove(obj, s, lbl_803E8304, 0);
            *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8354;
        }
    } else if (!((ByteFlags *)((char *)inner + 0x14ec))->b01) {
        ObjAnim_SetCurrentMove(obj, s, lbl_803E8304, 0);
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8354;
    }
    {
        f32 v = interpolate((f32)(s32)*(int *)((char *)q + 0x47c), lbl_803E8338 / *(f32 *)((char *)q + 0x428), timeDelta);
        f32 cap = timeDelta * (*(f32 *)((char *)q + 0x42c) * *(f32 *)((char *)q + 0x420));
        if (v >= cap) {
            v = cap;
        }
        if (*(int *)((char *)q + 0x480) < 0) {
            v = -v;
        }
        *(s16 *)((char *)q + 0x478) = (s16)(int)(lbl_803E8348 * v + (f32)(s32)*(s16 *)((char *)q + 0x478));
    }
    {
        f32 v = interpolate((f32)(s32)*(int *)((char *)q + 0x488), lbl_803E8338 / *(f32 *)((char *)q + 0x430), timeDelta);
        f32 cap = *(f32 *)((char *)q + 0x434) * timeDelta;
        if (v >= cap) {
            v = cap;
        }
        if (*(int *)((char *)q + 0x48c) < 0) {
            v = -v;
        }
        *(s16 *)((char *)q + 0x484) = (s16)(int)(lbl_803E8348 * v + (f32)(s32)*(s16 *)((char *)q + 0x484));
    }
    fn_802BCA10(obj, q, p2);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_hitDetect(int obj)
{
    void *hitObj;
    f32 hx;
    f32 hy;
    f32 hz;
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    EWColorTbl rows;
    int inner = *(int *)((char *)obj + 0xb8);
    int p54 = *(int *)((char *)obj + 0x54);
    rows = lbl_802C2CC0;
    if (!(*(u16 *)((char *)obj + 0xb0) & 0x1000)) {
        if (*(s8 *)((char *)p54 + 0xad) != 0) {
            int i = *(s8 *)((char *)p54 + 0xac);
            if (i < 0) {
                i = 0;
            } else if (i > 0x23) {
                i = 0x23;
            }
            v.mat[0] = lbl_803E8338;
            v.angles[2] = 0;
            v.angles[1] = 0;
            v.angles[0] = 0;
            v.mat[1] = *(f32 *)((char *)p54 + 0x3c);
            v.mat[2] = *(f32 *)((char *)p54 + 0x40);
            v.mat[3] = *(f32 *)((char *)p54 + 0x44);
            (*(void (*)(int, int, void *, int, int, void *))(*(int *)(*(int *)lbl_803DE4D0 + 0x4)))(0, 1, &v, 0x401, -1, rows.m[lbl_803352AC[i]]);
            *(u8 *)(*(int *)((char *)obj + 0x54) + 0x70) = 1;
            doRumble(lbl_803E8330);
        }
        if (*(int *)((char *)p54 + 0x50) != 0) {
            doRumble(lbl_803E8330);
        }
        *(s16 *)obj = *(s16 *)((char *)inner + 0xfd0);
        if (*(s16 *)((char *)inner + 0x274) != 3) {
            int hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, 0, &hx, &hy, &hz);
            if (hit != 0) {
                if (objGetFlagsE5_2(obj) != 0 && *(u8 *)((char *)inner + 0x14e6) == 2) {
                    return;
                }
                Obj_SpawnHitLightAndFade(obj, &hx, lbl_803E8368);
                if (hit == 0x1a) {
                    return;
                }
                if (hitObj == Obj_GetPlayerObject()) {
                    return;
                }
                if (*(s16 *)((char *)hitObj + 0x46) == 0x23) {
                    return;
                }
                objAudioFn_800393f8(obj, (void *)(inner + 0x3bc), 0x28e, 0x1000, -1, 1);
                {
                    s16 d = *(s16 *)obj - (u16)*(s16 *)hitObj;
                    if (d > 0x8000) {
                        d -= 0xffff;
                    }
                    if (d < -0x8000) {
                        d += 0xffff;
                    }
                    if (d > 0x4000 || d < -0x4000) {
                        ((ByteFlags *)((char *)inner + 0x14ec))->b80 = 0;
                    } else {
                        ((ByteFlags *)((char *)inner + 0x14ec))->b80 = 1;
                    }
                }
                *(int *)((char *)inner + 0x14d8) = *(s16 *)((char *)inner + 0x274);
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 3);
            }
        }
        if (*(int *)inner & 0x800000) {
            if ((*(u8 *)((char *)inner + 0x262) != 0 || (*(s8 *)((char *)inner + 0x264) & 0xf0)) &&
                *(f32 *)((char *)inner + 0xf68) <= lbl_803E8304 && *(f32 *)((char *)inner + 0x280) > lbl_803E836C) {
                doRumble((f32)(int)randomGetRange(2, 5));
                *(f32 *)((char *)inner + 0xf68) = lbl_803E8370;
                Sfx_PlayFromObject(obj, 0x404);
            }
            if (*(u8 *)((char *)inner + 0x262) != 0 || (*(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) & 8)) {
                f32 spd;
                f32 vcos;
                f32 vsin;
                spd = sqrtf(*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) + *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c));
                *(f32 *)((char *)obj + 0x24) = oneOverTimeDelta * (*(f32 *)((char *)obj + 0x18) - *(f32 *)((char *)obj + 0x8c));
                *(f32 *)((char *)obj + 0x2c) = oneOverTimeDelta * (*(f32 *)((char *)obj + 0x20) - *(f32 *)((char *)obj + 0x94));
                vcos = fn_80293E80((lbl_803E8374 * (f32)(s32)*(s16 *)((char *)inner + 0xfdc)) / lbl_803E8320);
                vsin = sin((lbl_803E8374 * (f32)(s32)*(s16 *)((char *)inner + 0xfdc)) / lbl_803E8320);
                *(f32 *)((char *)inner + 0x280) = -*(f32 *)((char *)obj + 0x2c) * vsin - *(f32 *)((char *)obj + 0x24) * vcos;
                *(f32 *)((char *)inner + 0x280) *= lbl_803E8314;
                {
                    f32 vv = *(f32 *)((char *)inner + 0x280);
                    f32 t = lbl_803E8378;
                    if ((lbl_803E8378 <= vv) && (t = vv, *(f32 *)((char *)inner + 0xf5c) < vv)) {
                        t = *(f32 *)((char *)inner + 0xf5c);
                    }
                    *(f32 *)((char *)inner + 0x280) = t;
                }
                {
                    f32 vv = *(f32 *)((char *)inner + 0x280);
                    f32 t = lbl_803E8304;
                    if ((lbl_803E8304 <= vv) && (t = vv, spd < vv)) {
                        t = spd;
                    }
                    *(f32 *)((char *)inner + 0x280) = t;
                }
                if (!((ByteFlags *)((char *)inner + 0xf48))->b40) {
                    *(f32 *)((char *)inner + 0x294) = *(f32 *)((char *)inner + 0x280);
                }
            }
            *(int *)inner &= ~0x800000;
        }
        *(f32 *)((char *)inner + 0xf68) -= timeDelta;
        if (*(f32 *)((char *)inner + 0xf68) < lbl_803E8304) {
            *(f32 *)((char *)inner + 0xf68) = lbl_803E8304;
        }
        if ((void *)inner != NULL) {
            fn_80026C54(*(int *)((char *)inner + 0x14f8));
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_update(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    Obj_GetPlayerObject();
    {
        int p54 = *(int *)((char *)obj + 0x54);
        *(u8 *)(p54 + 0x6e) = 0;
        *(u8 *)(p54 + 0x6f) = 0;
    }
    if (*(void **)((char *)inner + 0xb54) == NULL && Obj_IsLoadingLocked() != 0) {
        int setup = Obj_AllocObjectSetup(0x18, 0x6f5);
        int newObj = Obj_SetupObject(setup, 4, *(s8 *)((char *)obj + 0xac), -1, *(int *)((char *)obj + 0x30));
        ObjLink_AttachChild(obj, newObj, 2);
        *(int *)((char *)inner + 0xb54) = newObj;
    }
    *(s16 *)((char *)inner + 0x14de) = 5;
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    if (*(u8 *)((char *)inner + 0x14e6) == 2) {
        setAButtonIcon(0x13);
        *(u8 *)((char *)obj + 0xaf) |= 8;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6a) = 0xf4;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6b) = 0xf4;
        fn_802BE6E8(obj, (int)timeDelta, -1);
    } else {
        f32 z;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6a) = 0;
        *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6b) = 0;
        z = lbl_803E8304;
        *(f32 *)((char *)inner + 0x294) = z;
        *(f32 *)((char *)inner + 0x284) = z;
        *(f32 *)((char *)inner + 0x280) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
        fn_802BE6E8(obj, framesThisStep, -1);
    }
    characterDoEyeAnims(obj, inner + 0x38c);
    objAnimFn_80038f38(obj, inner + 0x3bc);
    dll_2E_func03(obj, inner + 0x3ec);
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        ((ByteFlags *)((char *)inner + 0x14ec))->b10 = 1;
        if ((*(int (*)(int))(*(int *)(*gGameUIInterface + 0x20)))(0xc1) != 0) {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
            buttonDisable(0, 0x100);
            *(s16 *)((char *)inner + 0x14e2) += 4;
            GameBit_Set(0xc1, GameBit_Get(0xc1) - 1);
        } else if (*(s8 *)((char *)inner + 0x14f4) != -1) {
            if ((*(int (*)(void))(*(int *)(*gGameUIInterface + 0x1c)))() == 0) {
                if (((ByteFlags *)((char *)inner + 0x14ec))->b08 == 0) {
                    (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(*(s8 *)((char *)inner + 0x14f4), obj, -1);
                    buttonDisable(0, 0x100);
                } else {
                    ((ByteFlags *)((char *)inner + 0x14ec))->b10 = 1;
                }
            }
        }
    }
    *(s8 *)((char *)inner + 0x264) |= 0x10;
    {
        f32 saved = *(f32 *)((char *)obj + 0x28);
        u8 mode;
        *(f32 *)((char *)obj + 0x28) = lbl_803E8304;
        *(int *)((char *)inner + 0x314) &= ~7;
        mode = *(u8 *)((char *)inner + 0x13fe);
        objAudioFn_8006edcc(obj, *(int *)((char *)inner + 0x314), mode, inner + 0xb18, inner + 0x4, *(f32 *)((char *)inner + 0x280), (mode == 8) ? lbl_803E837C : lbl_803E8380);
        *(f32 *)((char *)obj + 0x28) = saved;
    }
    if (*(u16 *)((char *)inner + 0x1430) & 8) {
        f32 vecA[3];
        struct {
            s16 angles[4];
            f32 mat[4];
        } w;
        int i;
        int j;
        int p;
        f32 c835c;
        f32 c8338;
        vecA[0] = lbl_803E833C * *(f32 *)((char *)obj + 0x24);
        vecA[1] = lbl_803E8304;
        vecA[2] = lbl_803E833C * *(f32 *)((char *)obj + 0x2c);
        c835c = lbl_803E835C;
        c8338 = lbl_803E8338;
        for (i = 0, p = inner; i < 4; i++) {
            w.mat[1] = c835c * *(f32 *)((char *)obj + 0x24) + *(f32 *)((char *)p + 0xb18);
            w.mat[2] = *(f32 *)((char *)p + 0xb1c);
            w.mat[3] = c835c * *(f32 *)((char *)obj + 0x2c) + *(f32 *)((char *)p + 0xb20);
            w.mat[0] = c8338;
            w.angles[0] = 2;
            for (j = 2; j != 0; j--) {
                (*(void (*)(int, int, void *, int, int, void *))(*(int *)(*gPartfxInterface + 0x8)))(obj, 0x7e6, &w, 0x200001, -1, vecA);
            }
            p += 0xc;
        }
        *(u16 *)((char *)inner + 0x1430) &= ~8;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_init(int obj, int p2)
{
    register u8 *base = lbl_803351F8;
    int inner = *(int *)((char *)obj + 0xb8);
    int stk;
    EWPathRange r2;
    EWPathRange r1;
    int q;
    stk = lbl_803E82D8;
    r2 = lbl_802C2CA8;
    r1 = lbl_802C2CB4;
    *(s16 *)obj = (s16)(*(s8 *)((char *)p2 + 0x18) << 8);
    *(int *)((char *)obj + 0xbc) = (int)fn_802BDBE8;
    ObjGroup_AddObject(obj, 0xa);
    *(u8 *)((char *)inner + 0x14e8) = *(u8 *)((char *)p2 + 0x19);
    *(s16 *)((char *)inner + 0x14de) = 5;
    *(s8 *)((char *)inner + 0x14f4) = -1;
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 4, 1);
    *(int *)inner |= 0x4000;
    *(f32 *)((char *)inner + 0x2a4) = lbl_803E8384;
    q = inner + 0x4;
    (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 0, 0x48683, 1);
    (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 4, (int)(base + 0xc), (int)(base + 0x3c), &stk);
    (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 1, (int)(base + 0x4c), (int)(base + 0x64), 8);
    *(u8 *)((char *)q + 0x264) = 0x28;
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, q);
    ObjHits_EnableObject(obj);
    *(s16 *)(*(int *)((char *)obj + 0x54) + 0xb2) = 9;
    dll_2E_func05(obj, inner + 0x3ec, -0x2000, 0x31c7, 2);
    dll_2E_func09(inner + 0x3ec, &r1, &r2, 2);
    fn_80113F94(inner + 0x3ec, lbl_803E8388);
    *(u8 *)((char *)inner + 0x9fd) |= 2;
    *(f32 *)((char *)inner + 0x1444) = lbl_803E82E8;
    *(s16 *)((char *)inner + 0x14e2) = *(s16 *)((char *)p2 + 0x1a);
    *(int *)((char *)inner + 0xf50) = (int)(base + 0xd8);
    *(int *)((char *)inner + 0xf58) = (int)(base + 0x84);
    {
        f32 v = lbl_803E8338;
        *(f32 *)((char *)inner + 0x138c) = v;
        *(f32 *)((char *)inner + 0x1384) = v;
    }
    *(f32 *)((char *)inner + 0x1388) = lbl_803E838C;
    *(int *)((char *)inner + 0xfa8) = (int)(base + 0x118);
    *(u8 *)((char *)inner + 0x1428) = 0x29;
    *(int *)((char *)inner + 0xfac) = (int)(base + 0x1bc);
    *(u8 *)((char *)inner + 0x1429) = 0x29;
    *(int *)((char *)inner + 0xfb0) = (int)(base + 0x260);
    *(u8 *)((char *)inner + 0x142a) = 0x2e;
    *(int *)((char *)inner + 0xfb4) = (int)(base + 0x1bc);
    *(u8 *)((char *)inner + 0x142b) = 0x29;
    *(int *)((char *)inner + 0xfb8) = (int)(base + 0x260);
    *(u8 *)((char *)inner + 0x142c) = 0x2e;
    *(f32 *)((char *)inner + 0x1338) = GXIndTexMtxScale1024;
    {
        s16 h = *(s16 *)obj;
        *(int *)((char *)inner + 0xfec) = h;
        *(int *)((char *)inner + 0xfcc) = h;
        *(s16 *)((char *)inner + 0xfdc) = h;
        *(s16 *)((char *)inner + 0xfd0) = h;
    }
    ((ByteFlags *)((char *)inner + 0x14ec))->b08 = 0;
    *(u8 *)((char *)inner + 0x14f4) = 2;
    storeZeroToFloatParam(inner + 0x14f0);
    s16toFloat(inner + 0x14f0, 0x1e);
    ((ByteFlags *)((char *)inner + 0x14ec))->b02 = 0;
    *(u8 *)((char *)inner + 0x14f5) = 1;
    *(int *)((char *)inner + 0xb54) = 0;
    if (GameBit_Get(0x9ec) != 0) {
        *(u8 *)((char *)inner + 0x14ed) = 1;
    }
    *(int *)((char *)inner + 0x14f8) = allocModelStruct2(&lbl_803DC768, 1);
    tailFn_80026c38(*(int *)((char *)inner + 0x14f8), lbl_803E8324, lbl_803E831C, lbl_803E8394);
    *(int *)((char *)obj + 0x108) = (int)fn_802BC788;
    fn_80026C30(*(int *)((char *)inner + 0x14f8), 1);
}
#pragma peephole reset
#pragma scheduling reset
