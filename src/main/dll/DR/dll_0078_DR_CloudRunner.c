#include "main/dll/DR/dr_802bbc10_shared.h"

#define SFXtr_cnflyby6 0x11E

int fn_802BF728(void) { return 0x0; }

void DR_CloudRunner_func21(void) {}

int DR_CloudRunner_func20(void) { return 0x0; }

int DR_CloudRunner_func16(void) { return 0x0; }

int DR_CloudRunner_render2(void) { return 0x0; }

int DR_CloudRunner_setScale(void) { return 0x0; }

int DR_CloudRunner_getExtraSize(void) { return 0xbc8; }

int DR_CloudRunner_getObjectTypeId(void) { return 0x43; }

void DR_CloudRunner_release(void) {}

#pragma scheduling off
#pragma peephole off
f32 DR_CloudRunner_func19(int obj, f32 *out)
{
    *out = lbl_803E83E8;
    return lbl_803E83A4;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_func18(int obj, f32 *a, int *b)
{
    *a = lbl_803E83A4;
    *b = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_func11(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xbb8) != 0) {
        return 1;
    }
    return 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_func22(int obj)
{
    fn_8003B950(ObjPath_GetPointModelMtx(obj, 2));
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_func14(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xbb7) != 0) {
        return 2;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_modelMtxFn(int obj, int a, int b, int c)
{
    ObjPath_GetPointWorldPosition(obj, 2, a, b, c, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802BF730(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 v;
    if (*(s16 *)((char *)inner + 0xbb0) == 0) {
        v = *(u8 *)((char *)obj + 0x36);
        *(u8 *)((char *)obj + 0x36) = v - framesThisStep;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_free(int obj)
{
    GameBit_Set(0x7aa, *(s16 *)((char *)*(int *)((char *)obj + 0xb8) + 0xbb0));
    ObjGroup_RemoveObject(obj, 0xa);
    ObjGroup_RemoveObject(obj, 0x26);
    (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_initialise(void)
{
    ((void **)lbl_803DB1C0)[0] = (void *)fn_802C0B84;
    ((void **)lbl_803DB1C0)[1] = (void *)fn_802C0A5C;
    ((void **)lbl_803DB1C0)[2] = (void *)fn_802C0978;
    ((void **)lbl_803DB1C0)[3] = (void *)fn_802C0830;
    ((void **)lbl_803DB1C0)[4] = (void *)fn_802C0550;
    ((void **)lbl_803DB1C0)[5] = (void *)fn_802BF934;
    ((void **)lbl_803DB1C0)[6] = (void *)fn_802BF75C;
    ((void **)lbl_803DB1C0)[7] = (void *)fn_802BF730;
    lbl_803DE4E0 = (void *)fn_802BF728;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802C0978(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        *(s16 *)((char *)p2 + 0x338) = 0;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E83F4;
        *(f32 *)((char *)p2 + 0x2b8) = lbl_803E83F8;
        if (*(s16 *)((char *)obj + 0xa0) != 0) {
            ObjAnim_SetCurrentMove(obj, 0, fz, 0);
        }
        if (((ByteFlags *)((char *)inner + 0xbc0))->b20) {
            ((ByteFlags *)((char *)inner + 0xbc0))->b20 = 0;
            *(u8 *)((char *)p2 + 0x25f) = 0;
        }
    }
    if (*(f32 *)((char *)p2 + 0x298) < lbl_803E83BC) {
        *(s16 *)((char *)p2 + 0x334) = 0;
        *(s16 *)((char *)p2 + 0x336) = 0;
        *(f32 *)((char *)p2 + 0x298) = lbl_803E83A4;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802C0A5C(int obj, int p2)
{
    int q = *(int *)((char *)obj + 0x4c);
    int inner;
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 fz;
        ObjHits_DisableObject(obj);
        *(u8 *)((char *)p2 + 0x25f) = 0;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8408;
        fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        return 0;
    }
    inner = *(int *)((char *)obj + 0xb8);
    Vec_distance(obj + 0x18, (int)Obj_GetPlayerObject() + 0x18);
    if (RandomTimer_UpdateRangeTrigger(inner + 0xb54, lbl_803E83F8, lbl_803E840C)) {
        Sfx_PlayFromObject(obj, 0x464);
    }
    if (GameBit_Get(*(s16 *)((char *)q + 0x1e))) {
        *(int *)((char *)obj + 0xf4) = 0;
        ObjHits_EnableObject(obj);
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((ByteFlags *)((char *)inner + 0xbc0))->b10 = *(s16 *)((char *)inner + 0xbb0) > 0;
        *(s16 *)((char *)obj + 0) = lbl_803DC79A;
        return 3;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802C0830(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        ((ByteFlags *)((char *)inner + 0xbc0))->b10 = 0;
        *(f32 *)((char *)obj + 0x28) = lbl_803E83A4;
        if (((ByteFlags *)((char *)inner + 0xbc0))->b20) {
            ((ByteFlags *)((char *)inner + 0xbc0))->b20 = 0;
            fn_802BF0C8(obj, p2, ((ByteFlags *)((char *)inner + 0xbc0))->b20);
        }
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x203:
        if (*(s16 *)((char *)inner + 0xbb0) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x20c, lbl_803E83A4, 0);
            *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8408;
        }
        break;
    case 0x20c:
        if (*(s8 *)((char *)p2 + 0x346) != 0) {
            *(u8 *)((char *)inner + 0xad5) &= ~2;
            return 3;
        }
        break;
    default: {
        f32 fz;
        ObjAnim_SetCurrentMove(obj, 0x203, lbl_803E83A4, 0);
        *(u8 *)((char *)inner + 0xad5) |= 2;
        fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8408;
        break;
    }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int *)((char *)p1 + 0xb8);
    if (*(int *)((char *)p1 + 0xf4) == 0) {
        if (vis == -1) {
            objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E83A8);
            ObjPath_GetPointWorldPosition(p1, 3, (char *)inner + 0xae8, (char *)inner + 0xaec, (char *)inner + 0xaf0, 0);
        }
        if (*(u8 *)((char *)inner + 0xbb2) != 2 && vis != 0) {
            objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E83A8);
            dll_2E_func06(p1, (char *)inner + 0x4c4, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802C0B84(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xbb4) == 0) {
        return 2;
    }
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    ((ByteFlags *)((char *)inner + 0xbc0))->b10 = *(s16 *)((char *)inner + 0xbb0) > 0;
    return 3;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_func17(int obj, int param)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xbb2) = (u8)param;
    if (param == 1) {
        s16 t;
        *(u8 *)((char *)inner + 0x464) = 0;
        t = *(s16 *)((char *)obj + 0xb4);
        if (t != -1) {
            (*(void (*)(int))(*(int *)(*gObjectTriggerInterface + 0x4c)))(t);
        }
    } else {
        *(u8 *)((char *)inner + 0x464) = 1;
    }
    if (param == 2) {
        GameBit_Set(0xed7, 1);
    } else {
        GameBit_Set(0xed7, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_SeqFn(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int local = 1;
    int i;
    *(u8 *)((char *)obj + 0xaf) |= 8;
    for (i = 0; i < *(u8 *)((char *)p3 + 0x8b); i++) {
        int idx = i + 0x81;
        if ((int)*(u8 *)((char *)p3 + idx) == 1) {
            (*(void (*)(int, int, f32, int *, int))(*(int *)(*gRomCurveInterface + 0x8c)))(inner + 0x35c, obj, lbl_803E8410, &local, 0xf);
        }
    }
    ((ByteFlags *)((char *)inner + 0xbc1))->b80 = 1;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_func15(int obj, f32 *a, f32 *b, f32 *c)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    void *src = Obj_GetPlayerObject();
    if (src == NULL) {
        src = (void *)obj;
    }
    v.mat[1] = *(f32 *)((char *)src + 0xc);
    v.mat[2] = *(f32 *)((char *)src + 0x10);
    v.mat[3] = *(f32 *)((char *)src + 0x14);
    v.angles[0] = *(s16 *)((char *)src + 0);
    v.angles[1] = *(s16 *)((char *)src + 2);
    v.angles[2] = *(s16 *)((char *)src + 4);
    v.mat[0] = lbl_803E83A8;
    setMatrixFromObjectPos(matrix, v.angles);
    Matrix_TransformPoint(matrix, lbl_803E83A4, lbl_803DC78C, lbl_803DC790, a, b, c);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_init(int obj, int p2)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } stk;
    int inner;
    int r;
    *(s16 *)((char *)obj + 0) = (s16)((s8)*(s8 *)((char *)p2 + 0x18) << 8);
    *(int *)((char *)obj + 0xbc) = (int)DR_CloudRunner_SeqFn;
    ObjGroup_AddObject(obj, 0xa);
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xbb4) = *(u8 *)((char *)p2 + 0x19);
    *(s16 *)((char *)inner + 0xbae) = 5;
    *(s16 *)((char *)inner + 0xbb0) = *(s16 *)((char *)p2 + 0x1a);
    *(s8 *)((char *)inner + 0xbc4) = -1;
    *(f32 *)((char *)inner + 0xb50) = (f32)*(s16 *)((char *)p2 + 0x1c) / lbl_803E8414;
    if (*(void **)((char *)obj + 0x64) != NULL) {
        *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) |= 0xa10;
    }
    r = GameBit_Get(0x7a9);
    if (r != 0) {
        dll_2E_func0A(r + 0x13, &stk);
        *(f32 *)((char *)obj + 0xc) = stk.mat[1];
        *(f32 *)((char *)obj + 0x10) = stk.mat[2];
        *(f32 *)((char *)obj + 0x14) = stk.mat[3];
        *(s16 *)((char *)obj + 0) = stk.angles[0];
    }
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 8, 1);
    *(f32 *)((char *)inner + 0x2a4) = lbl_803E8424;
    fn_802BF0C8(obj, inner, ((ByteFlags *)((char *)inner + 0xbc0))->b20);
    dll_2E_func05(obj, inner + 0x4c4, -0x11c7, 0x1555, 1);
    dll_2E_func08(inner + 0x4c4, 0x12c, 0x78);
    ObjGroup_AddObject(obj, 0x26);
    ((ByteFlags *)((char *)inner + 0xbc0))->b01 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802BF0C8(int obj, int p2, int mode)
{
    u8 *base = lbl_803356F0;
    int stk = lbl_803E83A0;
    int q = p2 + 0x4;
    u32 m;
    *(u8 *)((char *)q + 0x25b) = 1;
    m = (u8)mode;
    if (m == 1) {
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 0, 0x42087, 0);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 1, (int)(base + 0x18), (int)&lbl_803DC774, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 1, (int)(base + 0xc), (int)&lbl_803DC770, &stk);
    } else if (m == 2) {
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 3, 0x42087, 0);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 2, (int)(base + 0x30), (int)&lbl_803DC77C, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 1, (int)(base + 0x24), (int)&lbl_803DC778, &stk);
    } else if (m == 0) {
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 3, 0x42087, 0);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 2, (int)(base + 0x48), (int)&lbl_803DC784, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 1, (int)(base + 0x3c), (int)&lbl_803DC780, &stk);
    }
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, q);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802C11BC(int obj, int p2, f32 f)
{
    int inner;
    int flag;
    int slot;
    if (p2 != -1) {
        flag = (((framesThisStep - 1) - p2) == 0);
    } else {
        flag = 1;
    }
    slot = (int)Camera_GetCurrentViewSlot();
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0x354) = 0;
    *(int *)((char *)inner + 0) &= ~0x8000;
    *(int *)((char *)inner + 0) |= 0x200000;
    if (*(u8 *)((char *)inner + 0xbb2) == 2) {
        *(f32 *)((char *)inner + 0x290) = (f32)(s8)padGetStickX(0);
        *(f32 *)((char *)inner + 0x28c) = (f32)(s8)padGetStickY(0);
        *(int *)((char *)inner + 0x31c) = getButtonsJustPressed(0);
        *(int *)((char *)inner + 0x318) = getButtonsHeld(0);
        *(s16 *)((char *)inner + 0x330) = *(s16 *)slot;
        if (((ByteFlags *)((char *)inner + 0xbc0))->b01 != 0) {
            Obj_UpdateRomCurveFollowVelocity(obj, inner + 0x35c, *(f32 *)((char *)inner + 0xb50), lbl_803E83B4, lbl_803E8414, 1);
        }
    } else {
        f32 v = lbl_803E83A4;
        *(f32 *)((char *)inner + 0x290) = v;
        *(f32 *)((char *)inner + 0x28c) = v;
        *(int *)((char *)inner + 0x31c) = 0;
        *(int *)((char *)inner + 0x318) = 0;
        *(s16 *)((char *)inner + 0x330) = 0;
    }
    *(int *)((char *)inner + 0) |= 0x400000;
    if (flag != 0) {
        *(int *)((char *)inner + 0) &= ~0x400000;
    }
    (*(void (*)(int, int, f32, f32, int, void *))(*(int *)(*gPlayerInterface + 0x8)))(obj, inner, f, timeDelta, (int)lbl_803DB1C0, &lbl_803DE4E0);
    if ((*(int *)((char *)inner + 0x314) & 1) != 0) {
        fn_802BF4D8(obj);
    }
    if (((ByteFlags *)((char *)inner + 0xbc0))->b02 != 0) {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner + 0xbb0) - lbl_803DE4D8);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_update(int obj)
{
    int inner;
    Obj_GetPlayerObject();
    inner = *(int *)((char *)obj + 0xb8);
    *(s16 *)((char *)inner + 0xbae) = 5;
    fn_80137948(sOnCloudFormat, GameBit_Get(0xed7));
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    if (*(u8 *)((char *)inner + 0xbb2) == 2) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
        fn_802C11BC(obj, -1, timeDelta);
        *(int *)((char *)*(int *)((char *)obj + 0x50) + 0x44) |= 0x200000;
    } else {
        *(u8 *)((char *)inner + 0x25f) = 0;
        fn_802C11BC(obj, -1, timeDelta);
        *(int *)((char *)*(int *)((char *)obj + 0x50) + 0x44) &= ~0x200000;
    }
    if (*(s8 *)((char *)inner + 0xbc3) != 0) {
        s8 v = *(s8 *)((char *)inner + 0xbc3) - framesThisStep;
        *(s8 *)((char *)inner + 0xbc3) = v;
        if (v < 0) {
            *(s8 *)((char *)inner + 0xbc3) = 0;
        }
    }
    if (*(u8 *)((char *)inner + 0xbb2) == 2) {
        ObjHits_MarkObjectPositionDirty(obj);
        *(u8 *)((char *)inner + 0xad5) |= 1;
    } else {
        *(u8 *)((char *)inner + 0xad5) &= ~1;
    }
    dll_2E_func03(obj, inner + 0x4c4);
    objAnimFn_80038f38(obj, inner + 0x494);
    fn_8003B500(obj, inner + 0x464, lbl_803E83A4);
    characterDoEyeAnims(obj, inner + 0x464);
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        if (*(u8 *)((char *)inner + 0xbb2) == 0) {
            if (((ByteFlags *)((char *)inner + 0xbc0))->b10) {
                f32 vec[3];
                buttonDisable(0, 0x100);
                if ((*(int (*)(void))(*(int *)(*gMapEventInterface + 0x30)))() == 0) {
                    vec[0] = lbl_803E8418;
                    vec[1] = lbl_803E841C;
                    vec[2] = lbl_803E8420;
                    (*(void (*)(f32 *, int, int, int))(*(int *)(*gMapEventInterface + 0x24)))(vec, 0, 0, 0);
                }
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(4, obj, -1);
                *(int *)((char *)inner + 0xb04) = 0;
                *(u8 *)((char *)inner + 0xbb6) |= 4;
                *(u8 *)((char *)inner + 0xad5) |= 1;
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 4);
            } else {
                buttonDisable(0, 0x100);
                {
                    s8 t = *(s8 *)((char *)inner + 0xbc4);
                    if (t != -1) {
                        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(t, obj, -1);
                    }
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802BF4D8(int obj)
{
    f32 tr[2];
    f32 gB[2];
    f32 gC[2];
    f32 pos[3];
    f32 diff[3];
    f32 dir[3];
    struct {
        s16 angles[4];
        f32 mat[4];
    } s1;
    int inner = *(int *)((char *)obj + 0xb8);
    void *newObj;
    int setup;
    f32 dist;
    if (Obj_IsLoadingLocked(obj) == 0) {
        return;
    }
    Sfx_PlayFromObject(obj, SFXtr_cnflyby6);
    setup = Obj_AllocObjectSetup(0x24, 0x42a);
    *(u8 *)((char *)setup + 6) = 0xff;
    *(u8 *)((char *)setup + 7) = 0xff;
    *(u8 *)((char *)setup + 4) = 2;
    *(u8 *)((char *)setup + 5) = 1;
    *(f32 *)((char *)setup + 8) = *(f32 *)((char *)inner + 0xae8);
    *(f32 *)((char *)setup + 0xc) = *(f32 *)((char *)inner + 0xaec);
    *(f32 *)((char *)setup + 0x10) = *(f32 *)((char *)inner + 0xaf0);
    newObj = (void *)Obj_SetupObject(setup, 5, -1, -1, 0);
    if (newObj == NULL) {
        return;
    }
    s1.mat[1] = lbl_803E83A4;
    s1.mat[2] = lbl_803E83A4;
    s1.mat[3] = lbl_803E83A4;
    s1.mat[0] = lbl_803E83A8;
    s1.angles[0] = *(s16 *)((char *)obj + 0);
    s1.angles[1] = (s16)((*(s16 *)((char *)obj + 2) - 0x190) >> 1);
    s1.angles[2] = 0;
    dir[0] = lbl_803E83A4;
    dir[1] = lbl_803E83A4;
    dir[2] = lbl_803E83AC;
    mathFn_80021ac8(s1.angles, dir);
    *(f32 *)((char *)newObj + 0x24) = dir[0];
    *(f32 *)((char *)newObj + 0x28) = dir[1];
    *(f32 *)((char *)newObj + 0x2c) = dir[2];
    pos[0] = lbl_803E83B0 * *(f32 *)((char *)newObj + 0x24);
    pos[1] = lbl_803E83B0 * *(f32 *)((char *)newObj + 0x28);
    pos[2] = lbl_803E83B0 * *(f32 *)((char *)newObj + 0x2c);
    pos[0] = *(f32 *)((char *)newObj + 0xc) + pos[0];
    pos[1] = *(f32 *)((char *)newObj + 0x10) + pos[1];
    pos[2] = *(f32 *)((char *)newObj + 0x14) + pos[2];
    voxmaps_worldToGrid((void *)(obj + 0x18), gC);
    voxmaps_worldToGrid(pos, gB);
    if (voxmaps_traceLine(gC, gB, tr, 0, 0) == 0) {
        voxmaps_gridToWorld(pos, tr);
        diff[0] = pos[0] - *(f32 *)((char *)newObj + 0xc);
        diff[1] = pos[1] - *(f32 *)((char *)newObj + 0x10);
        diff[2] = pos[2] - *(f32 *)((char *)newObj + 0x14);
        dist = sqrtf(diff[2] * diff[2] + (diff[0] * diff[0] + diff[1] * diff[1]));
    } else {
        dist = lbl_803E83B4;
    }
    *(int *)((char *)newObj + 0xf4) = (int)dist;
    *(int *)((char *)newObj + 0xf8) = obj;
    *(s16 *)((char *)newObj + 0x4) = 0;
    *(s16 *)((char *)newObj + 0x2) = 0;
    *(s16 *)((char *)newObj + 0) = 0;
    (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))((int)newObj, 0x66, 0, 2, -1, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_802C0550(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int a0;
    int a1;
    *(int *)((char *)p2 + 0) |= 0x1204000;
    *(u8 *)((char *)p2 + 0x25f) = 0;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 fz = lbl_803E83A4;
        int inner2;
        int q;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        inner2 = *(int *)((char *)obj + 0xb8);
        q = *(int *)((char *)obj + 0x4c);
        ((ByteFlags *)((char *)inner2 + 0xbc0))->b02 = 1;
        (*(void (*)(int, int))(*(int *)(*gGameUIInterface + 0x58)))(*(s16 *)((char *)q + 0x1a), 0x5de);
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner2 + 0xbb0));
        *(s16 *)((char *)p2 + 0x338) = 0;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E83F4;
        *(f32 *)((char *)p2 + 0x2b8) = lbl_803E83F8;
        ObjAnim_SetCurrentMove(obj, 1, lbl_803E83A4, 0);
        ((ByteFlags *)((char *)inner + 0xbc0))->b01 = 1;
    }
    {
        f32 fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
    }
    *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)inner + 0x3c4);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x3c8);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)inner + 0x3cc);
    a0 = (u16)getAngle(-*(f32 *)((char *)inner + 0x3d0), -*(f32 *)((char *)inner + 0x3d8));
    a1 = (u16)getAngle(*(f32 *)((char *)inner + 0x3d4),
                       sqrtf(*(f32 *)((char *)inner + 0x3d0) * *(f32 *)((char *)inner + 0x3d0) +
                             *(f32 *)((char *)inner + 0x3d8) * *(f32 *)((char *)inner + 0x3d8)));
    a0 = a0 - (u16)*(s16 *)((char *)obj + 0);
    if (a0 > 0x8000) {
        a0 -= 0xffff;
    }
    if (a0 < -0x8000) {
        a0 += 0xffff;
    }
    *(s16 *)((char *)obj + 0) =
        (f32)(s32)*(s16 *)((char *)obj + 0) + interpolate((f32)(s32)a0, lbl_803E83FC, timeDelta);
    a1 = a1 - (u16)*(s16 *)((char *)obj + 2);
    if (a1 > 0x8000) {
        a1 -= 0xffff;
    }
    if (a1 < -0x8000) {
        a1 += 0xffff;
    }
    *(s16 *)((char *)obj + 2) =
        (f32)(s32)*(s16 *)((char *)obj + 2) + interpolate((f32)(s32)a1, lbl_803E83FC, timeDelta);
    *(s16 *)((char *)obj + 4) = (s16)(a0 >> 5);
    {
        int v = *(s16 *)((char *)obj + 4);
        if (v < -0x1000) {
            v = -0x1000;
        } else if (v > 0x1000) {
            v = 0x1000;
        }
        *(s16 *)((char *)obj + 4) = (s16)v;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
