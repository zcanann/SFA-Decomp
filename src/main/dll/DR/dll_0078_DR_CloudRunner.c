#include "main/dll/DR/dr_802bbc10_shared.h"
#include "main/dll/baddie_state.h"
#include "global.h"

/* DR_CloudRunner_getExtraSize == 0xbc8; BaddieState head + family tail. */
typedef struct CloudRunnerState {
    BaddieState baddie;
    u8 pad35C[0x3c4 - 0x35c];
    f32 unk3C4;
    f32 unk3C8;
    f32 unk3CC;
    f32 unk3D0;
    f32 unk3D4;
    f32 unk3D8;
    u8 pad3DC[0x464 - 0x3dc];
    u8 unk464;
    u8 pad465[0xad5 - 0x465];
    u8 unkAD5;
    u8 padAD6[0xae8 - 0xad6];
    f32 unkAE8;
    f32 unkAEC;
    f32 unkAF0;
    f32 unkAF4;
    f32 unkAF8;
    f32 unkAFC;
    u8 padB00[4];
    int unkB04;
    u8 padB08[0xb50 - 0xb08];
    f32 unkB50;
    u8 padB54[0xbae - 0xb54];
    s16 unkBAE;
    s16 unkBB0;
    u8 unkBB2;
    u8 padBB3;
    u8 unkBB4;
    u8 padBB5;
    u8 unkBB6;
    u8 unkBB7;
    u8 unkBB8;
    u8 padBB9;
    s16 unkBBA;
    s16 unkBBC;
    s16 unkBBE;
    u8 flagsBC0; /* ByteFlags */
    u8 flagsBC1; /* ByteFlags */
    u8 padBC2;
    s8 unkBC3;
    s8 unkBC4;
    u8 padBC5[3];
} CloudRunnerState;
STATIC_ASSERT(sizeof(CloudRunnerState) == 0xbc8);


#include "main/audio/sfx_ids.h"
#include "main/objanim_internal.h"
int DR_CloudRunner_defaultStateHandler(void) { return 0x0; }

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
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    if (inner->unkBB8 != 0) {
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
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    if (inner->unkBB7 != 0) {
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
int DR_CloudRunner_stateHandler07(int obj)
{
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    u8 v;
    if (inner->unkBB0 == 0) {
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
    ((void **)gDRCloudRunnerStateHandlers)[0] = (void *)DR_CloudRunner_stateHandler00;
    ((void **)gDRCloudRunnerStateHandlers)[1] = (void *)DR_CloudRunner_stateHandler01;
    ((void **)gDRCloudRunnerStateHandlers)[2] = (void *)DR_CloudRunner_stateHandler02;
    ((void **)gDRCloudRunnerStateHandlers)[3] = (void *)DR_CloudRunner_stateHandler03;
    ((void **)gDRCloudRunnerStateHandlers)[4] = (void *)DR_CloudRunner_stateHandler04;
    ((void **)gDRCloudRunnerStateHandlers)[5] = (void *)DR_CloudRunner_stateHandler05;
    ((void **)gDRCloudRunnerStateHandlers)[6] = (void *)DR_CloudRunner_stateHandler06;
    ((void **)gDRCloudRunnerStateHandlers)[7] = (void *)DR_CloudRunner_stateHandler07;
    gDRCloudRunnerDefaultStateHandler = (void *)DR_CloudRunner_defaultStateHandler;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_stateHandler02(int obj, int p2)
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
int DR_CloudRunner_stateHandler01(int obj, int p2)
{
    CloudRunnerState *inner;
    int q = *(int *)((char *)obj + 0x4c);
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
    inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    Vec_distance(obj + 0x18, (int)Obj_GetPlayerObject() + 0x18);
    if (RandomTimer_UpdateRangeTrigger((int)((char *)inner + 0xb54), lbl_803E83F8, lbl_803E840C)) {
        Sfx_PlayFromObject(obj, 0x464);
    }
    if ((u32)GameBit_Get(*(s16 *)((char *)q + 0x1e)) != 0) {
        *(int *)((char *)obj + 0xf4) = 0;
        ObjHits_EnableObject(obj);
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((ByteFlags *)&inner->flagsBC0)->b10 = inner->unkBB0 > 0;
        *(s16 *)((char *)obj + 0) = lbl_803DC79A;
        return 3;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_stateHandler03(int obj, int p2)
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
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)p1 + 0xb8);
    if (*(int *)((char *)p1 + 0xf4) == 0) {
        if (vis == -1) {
            objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E83A8);
            ObjPath_GetPointWorldPosition(p1, 3, (char *)(int)((char *)inner + 0xae8), (char *)(int)((char *)inner + 0xaec), (char *)(int)((char *)inner + 0xaf0), 0);
        }
        if (inner->unkBB2 != 2 && vis != 0) {
            objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E83A8);
            dll_2E_func06(p1, (char *)(int)((char *)inner + 0x4c4), 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_stateHandler00(int obj)
{
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    if (inner->unkBB4 == 0) {
        return 2;
    }
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    ((ByteFlags *)&inner->flagsBC0)->b10 = inner->unkBB0 > 0;
    return 3;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_func17(int obj, int param)
{
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    inner->unkBB2 = (u8)param;
    if (param == 1) {
        s16 t;
        inner->unk464 = 0;
        t = *(s16 *)((char *)obj + 0xb4);
        if (t != -1) {
            (*(void (*)(int))(*(int *)(*gObjectTriggerInterface + 0x4c)))(t);
        }
    } else {
        inner->unk464 = 1;
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

typedef struct {
    f32 x;
    f32 y;
    f32 z;
} Vec3x;


#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_stateHandler05(int obj, int p2, f32 f)
{
    u8 *base = (u8 *)lbl_803356F0;
    u32 idx;
    int flag = 0;
    CloudRunnerState *inner;
    int moveId;
    struct {
        s16 angles[4];
        f32 mat[4];
    } s1;
    Vec3x vecB;
    Vec3x vecC;
    Vec3x vecN;
    Vec3x vecD;
    Vec3x vecE;
    f32 speed;
    f32 accel;
    f32 grav;
    f32 d8;
    f32 mag;
    f32 adot;
    f32 animSpd;
    f32 spd;
    f32 dot;
    f32 dist;
    f32 t;
    f32 *lim;
    vecB = ((Vec3x *)lbl_802C2D00)[2];
    vecC = ((Vec3x *)lbl_802C2D00)[3];
    vecD = ((Vec3x *)lbl_802C2D00)[4];
    moveId = -1;
    inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    *(int *)((char *)p2 + 0) |= 0x200000;
    *(u8 *)((char *)p2 + 0x25f) = 0;
    if (*(s8 *)((char *)p2 + 0x346) != 0) {
        ((ByteFlags *)&inner->flagsBC0)->b80 = 0;
        ((ByteFlags *)&inner->flagsBC0)->b08 = 0;
        flag = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        if (!((ByteFlags *)&inner->flagsBC0)->b20) {
            ((ByteFlags *)&inner->flagsBC0)->b20 = 1;
            fn_802BF0C8(obj, p2, ((ByteFlags *)&inner->flagsBC0)->b20);
        }
        ObjAnim_SetCurrentMove(obj, *(s16 *)(base + 0x68), lbl_803E83A4, 0);
        inner->unkBBC = *(s16 *)(base + 0x74);
        inner->unkBBA = *(s16 *)((char *)obj + 0);
        inner->unkBBE = *(s16 *)((char *)obj + 4);
        {
            f32 fz = lbl_803E83A4;
            *(f32 *)((char *)p2 + 0x294) = fz;
            *(f32 *)((char *)p2 + 0x284) = fz;
            *(f32 *)((char *)p2 + 0x280) = fz;
            *(f32 *)((char *)obj + 0x24) = fz;
            *(f32 *)((char *)obj + 0x28) = fz;
            *(f32 *)((char *)obj + 0x2c) = fz;
        }
        flag = 1;
        ((ByteFlags *)&inner->flagsBC0)->b80 = 1;
        inner->unkAF4 = *(f32 *)((char *)obj + 0xc);
        inner->unkAF8 = *(f32 *)((char *)obj + 0x10);
        inner->unkAFC = *(f32 *)((char *)obj + 0x14);
    }
    *(int *)((char *)p2 + 0) |= 0x1000000;
    if (*(f32 *)((char *)p2 + 0x298) < lbl_803E83BC) {
        *(s16 *)((char *)p2 + 0x334) = 0;
        *(s16 *)((char *)p2 + 0x336) = 0;
        {
            f32 fz = lbl_803E83A4;
            *(f32 *)((char *)p2 + 0x290) = fz;
            *(f32 *)((char *)p2 + 0x28c) = fz;
            *(f32 *)((char *)p2 + 0x298) = fz;
        }
    }
    speed = *(f32 *)((char *)obj + 0x98);
    {
        s16 *p;
        for (idx = 0, p = (s16 *)(base + 0x60); *(s16 *)((char *)obj + 0xa0) != *p && idx < 6; idx++) {
            p += 1;
        }
    }
    if (idx >= 6) {
        idx = 4;
    }
    mag = sqrtf(*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c));
    if (!(mag < (spd = lbl_803E83A4))) goto spd_hi;
    goto spd_done;
spd_hi:
    if (!(mag > (spd = lbl_803E83C0))) goto spd_mag;
    goto spd_done;
spd_mag:
    spd = mag;
spd_done:
    *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) + (accel = ((grav = lbl_803E83C4) * spd) / lbl_803E83C0);
    *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) - grav;
    if (spd > lbl_803E83A4) {
        if ((int)idx >= 4) {
            s1.angles[2] = *(s16 *)((char *)obj + 4);
            s1.angles[1] = inner->unkBBC - 0x4000;
            s1.angles[0] = *(s16 *)((char *)obj + 0);
            s1.mat[1] = lbl_803E83A4;
            s1.mat[2] = lbl_803E83A4;
            s1.mat[3] = lbl_803E83A4;
            s1.mat[0] = lbl_803E83A8;
            vecD.z = lbl_803E83C8;
            vecRotateZXY(&s1, &vecC);
            vecRotateZXY(&s1, &vecD);
            vecC.x = vecC.x * accel;
            vecC.y = vecC.y * accel;
            vecC.z = vecC.z * accel;
            *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) + vecC.x;
            *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) + vecC.z;
        } else {
            s1.angles[2] = *(s16 *)((char *)obj + 4);
            s1.angles[1] = inner->unkBBC;
            s1.angles[0] = *(s16 *)((char *)obj + 0);
            s1.mat[1] = lbl_803E83A4;
            s1.mat[2] = lbl_803E83A4;
            s1.mat[3] = lbl_803E83A4;
            s1.mat[0] = lbl_803E83A8;
            vecRotateZXY(&s1, &vecD);
            vecN.x = -*(f32 *)((char *)obj + 0x24);
            vecN.y = -*(f32 *)((char *)obj + 0x28);
            vecN.z = -*(f32 *)((char *)obj + 0x2c);
            dot = vecD.z * vecN.z + (vecD.x * vecN.x + vecD.y * vecN.y);
            adot = dot >= lbl_803E83A4 ? dot : -dot;
            Vec3_Normalize(&vecN);
            vecN.x = vecN.x * (lbl_803E83CC * adot + lbl_803E83C4 * ((lbl_803E83D0 * adot) / lbl_803E83C0));
            vecN.y = vecN.y * (lbl_803E83CC * adot + lbl_803E83C4 * ((lbl_803E83D0 * adot) / lbl_803E83C0));
            vecN.z = vecN.z * (lbl_803E83CC * adot + lbl_803E83C4 * ((lbl_803E83D0 * adot) / lbl_803E83C0));
            *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) + vecN.x;
            *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) + vecN.y;
            *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) + vecN.z;
        }
    }
    if (*(f32 *)((char *)p2 + 0x298) > lbl_803E83BC) {
        s1.angles[2] = 0;
        s1.angles[1] = 0;
        s1.angles[0] = *(s16 *)((char *)obj + 0);
        s1.mat[1] = lbl_803E83A4;
        s1.mat[2] = lbl_803E83A4;
        s1.mat[3] = lbl_803E83A4;
        s1.mat[0] = lbl_803E83A8;
        vecC.x = *(f32 *)((char *)p2 + 0x290) * lbl_803E83D4 * *(f32 *)(base + ((int)idx >> 1) * 4 + 0x90);
        vecC.y = -*(f32 *)((char *)p2 + 0x28c) * lbl_803E83D4 * *(f32 *)(base + ((int)idx >> 1) * 4 + 0x9c);
        vecC.z = lbl_803E83A4;
        vecRotateZXY(&s1, &vecC);
        *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) + vecC.x;
        *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) + vecC.y;
        *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) + vecC.z;
    }
    if (((ByteFlags *)&inner->flagsBC0)->b80 & (*(f32 *)((char *)obj + 0x98) < lbl_803E83D8)) {
        s1.angles[2] = *(s16 *)((char *)obj + 4);
        s1.angles[1] = inner->unkBBC;
        s1.angles[0] = *(s16 *)((char *)obj + 0);
        s1.mat[1] = lbl_803E83A4;
        s1.mat[2] = lbl_803E83A4;
        s1.mat[3] = lbl_803E83A4;
        s1.mat[0] = lbl_803E83A8;
        vecRotateZXY(&s1, &vecB);
        *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) + vecB.x;
        *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) + vecB.y;
        *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) + vecB.z;
    }
    mag = sqrtf(*(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c) +
                (*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                 *(f32 *)((char *)obj + 0x28) * *(f32 *)((char *)obj + 0x28)));
    lim = (f32 *)(base + ((int)idx >> 1) * 4 + 0xa8);
    if (mag > *lim) {
        Vec3_Normalize((void *)(obj + 0x24));
        *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) * ((mag + *lim) * (d8 = lbl_803E83D8));
        *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) * (d8 * (mag + *lim));
        *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) * (d8 * (mag + *lim));
    } else {
        lim = (f32 *)(base + ((int)idx >> 1) * 4 + 0xb4);
        if (mag < *lim) {
            Vec3_Normalize((void *)(obj + 0x24));
            *(f32 *)((char *)obj + 0x24) = *(f32 *)((char *)obj + 0x24) * ((mag + *lim) * (d8 = lbl_803E83D8));
            *(f32 *)((char *)obj + 0x28) = *(f32 *)((char *)obj + 0x28) * (d8 * (mag + *lim));
            *(f32 *)((char *)obj + 0x2c) = *(f32 *)((char *)obj + 0x2c) * (d8 * (mag + *lim));
        }
    }
    if ((int)idx >= 4) {
        inner->unkBBA = inner->unkBBA - (int)*(f32 *)((char *)p2 + 0x290);
        inner->unkBBE = inner->unkBBE - ((int)*(f32 *)((char *)p2 + 0x290) << 3);
        *(s16 *)((char *)obj + 2) = *(s16 *)((char *)obj + 2) - (int)*(f32 *)((char *)p2 + 0x28c) * 3;
        inner->unkBBC = inner->unkBBC - (int)*(f32 *)((char *)p2 + 0x28c) * 3;
    } else {
        inner->unkBBA = inner->unkBBA - ((int)*(f32 *)((char *)p2 + 0x290) << 3);
        inner->unkBBE = inner->unkBBE - (int)*(f32 *)((char *)p2 + 0x290);
        *(s16 *)((char *)obj + 2) = *(s16 *)((char *)obj + 2) - (int)*(f32 *)((char *)p2 + 0x28c) * 6;
        inner->unkBBC = inner->unkBBC - ((int)*(f32 *)((char *)p2 + 0x28c) << 2);
    }
    if ((int)idx >= 4) {
        s16 ang;
        s16 diff;
        ang = (s16)(getAngle(*(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x2c)) + 0x8000);
        diff = ang - (u16)inner->unkBBA;
        if (diff > 0x8000) {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000) {
            diff = diff + 0xffff;
        }
        inner->unkBBA += diff / 64;
        inner->unkBBE += diff / 128;
    }
    {
        s16 lim2;
        if (inner->unkBBE > (lim2 = *(s16 *)((char *)&lbl_803DC794 + (idx & 0xfffffffe)))) {
            inner->unkBBE = lim2;
        } else {
            int neg = -lim2;
            if (inner->unkBBE < neg) {
                inner->unkBBE = (s16)neg;
            }
        }
    }
    if (inner->unkBBC > 0x4000) {
        inner->unkBBC = 0x4000;
    } else if (inner->unkBBC < -0x4000) {
        inner->unkBBC = -0x4000;
    }
    *(s16 *)((char *)obj + 0) = inner->unkBBA;
    *(s16 *)((char *)obj + 4) = inner->unkBBE;
    mag = sqrtf(*(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c) +
                (*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                 *(f32 *)((char *)obj + 0x28) * *(f32 *)((char *)obj + 0x28)));
    if (((ByteFlags *)&inner->flagsBC0)->b80 == 0 && (*(int *)((char *)p2 + 0x31c) & 0x200)) {
        Sfx_PlayFromObject(obj, 0x11d);
        ((ByteFlags *)&inner->flagsBC0)->b80 = 1;
        speed = lbl_803E83A4;
        flag = 1;
    }
    if (*(int *)((char *)p2 + 0) & 0x400000) {
        vecE.x = *(f32 *)((char *)obj + 0x80) - inner->unkAF4;
        vecE.y = *(f32 *)((char *)obj + 0x84) - inner->unkAF8;
        vecE.z = *(f32 *)((char *)obj + 0x88) - inner->unkAFC;
        dist = sqrtf(vecE.z * vecE.z + (vecE.x * vecE.x + vecE.y * vecE.y));
        if (!(dist < (t = lbl_803E83A4))) goto d_hi;
        goto d_done;
    d_hi:
        if (!(dist > (t = lbl_803E83DC))) goto d_dist;
        goto d_done;
    d_dist:
        t = dist;
    d_done:;
        Vec3_Normalize(&vecE);
        {
            f32 scale = ((t / lbl_803E83DC) * (lbl_803E83E0 + (mag / lbl_803E83C0) * (mag / lbl_803E83C0))) / f;
            vecE.x = vecE.x * scale;
            vecE.y = vecE.y * scale;
            vecE.z = vecE.z * scale;
        }
        if (vecE.y < lbl_803E83A4) {
            vecE.y = lbl_803E83A4;
        }
        vecE.y = vecE.y * lbl_803E83E4;
        t = vecE.y;
        if (vecE.y >= lbl_803E83A4) {
        } else {
            t = -vecE.y;
        }
        t = (lbl_803E83E8 - t) / lbl_803E83E8;
        if (t < lbl_803E83A4) {
            t = lbl_803E83A4;
        }
        vecE.x = vecE.x * t;
        vecE.y = vecE.y * t;
        vecE.z = vecE.z * t;
        *(f32 *)((char *)obj + 0x24) = vecE.x + *(f32 *)((char *)obj + 0x24);
        *(f32 *)((char *)obj + 0x28) = vecE.y + *(f32 *)((char *)obj + 0x28);
        *(f32 *)((char *)obj + 0x2c) = vecE.z + *(f32 *)((char *)obj + 0x2c);
        *(f32 *)((char *)obj + 0xc) = inner->unkAF4;
        *(f32 *)((char *)obj + 0x10) = inner->unkAF8;
        *(f32 *)((char *)obj + 0x14) = inner->unkAFC;
        objMove(obj, *(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x28), *(f32 *)((char *)obj + 0x2c));
        if ((*(s8 *)((char *)p2 + 0x264) & 0x10) && (int)(idx & 0xfe) == 0) {
            *(f32 *)((char *)obj + 0x28) = lbl_803E83EC;
            return 3;
        }
        inner->unkAF4 = *(f32 *)((char *)obj + 0xc);
        inner->unkAF8 = *(f32 *)((char *)obj + 0x10);
        inner->unkAFC = *(f32 *)((char *)obj + 0x14);
    } else {
        objMove(obj, *(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x28), *(f32 *)((char *)obj + 0x2c));
    }
    if (((ByteFlags *)&inner->flagsBC0)->b08 == 0 && (*(int *)((char *)p2 + 0x31c) & 0x100)) {
        buttonDisable(0, 0x100);
        moveId = 0x20d;
        animSpd = lbl_803E83F0;
        ((ByteFlags *)&inner->flagsBC0)->b08 = 1;
        flag = 1;
        speed = lbl_803E83A4;
    }
    if (flag != 0) {
        if (moveId == -1) {
            int masked;
            ObjAnim_SetCurrentMove(obj, *(s16 *)(base + ((masked = idx & 0xfe) + ((ByteFlags *)&inner->flagsBC0)->b80) * 2 + 0x60), speed, 0);
            *(f32 *)((char *)p2 + 0x2a0) = *(f32 *)(base + (masked >> 1) * 4 + 0xc0);
        } else {
            ObjAnim_SetCurrentMove(obj, moveId, speed, 0);
            *(f32 *)((char *)p2 + 0x2a0) = animSpd;
        }
    }
    return 0;
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
void DR_CloudRunner_func23(int obj, int mode, int *out)
{
    struct gbids {
        s16 a[4];
    } bits;
    struct curveids {
        int a[4];
    } curve;
    struct {
        s16 angles[4];
        f32 mat[4];
    } stk;
    CloudRunnerState *inner;
    Obj_GetPlayerObject();
    curve = *(struct curveids *)lbl_802C2D3C;
    bits = *(struct gbids *)&lbl_803E8398;
    inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    switch (mode) {
    case 2:
        if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) || ((ByteFlags *)&inner->flagsBC1)->b80) {
            *out = *(s16 *)((char *)obj + 0);
            lbl_803DE4DC = *(s16 *)((char *)obj + 0);
            ((ByteFlags *)&inner->flagsBC1)->b80 = 0;
        } else {
            s16 *p;
            s16 ang;
            int i;
            s16 diff;
            s16 step;
            ang = *(s16 *)((char *)obj + 0);
            i = 0;
            p = bits.a;
            do {
                if ((u32)GameBit_Get(*p) != 0) {
                    break;
                }
                p += 1;
                i += 1;
            } while (i < 4);
            if (i != 4 && dll_2E_func0A(curve.a[i], &stk) != 0) {
                s16 tmp = (s16)getAngle(stk.mat[1] - *(f32 *)((char *)obj + 0xc),
                                        stk.mat[3] - *(f32 *)((char *)obj + 0x14));
                ang = tmp + lbl_803DC79C;
            }
            diff = ang - (u16)lbl_803DE4DC;
            if (diff > 0x8000) {
                diff = diff - 0xffff;
            }
            if (diff < -0x8000) {
                diff = diff + 0xffff;
            }
            step = diff / 16;
            if (step < -0x50) {
                step = -0x50;
            } else if (step > 0x50) {
                step = 0x50;
            }
            lbl_803DE4DC = lbl_803DE4DC + (s16)step;
            *out = lbl_803DE4DC;
        }
        break;
    case 3:
        if (*(u16 *)((char *)obj + 0xb0) & 0x1000) {
            *out = 0;
        } else {
            *out = 1;
        }
        break;
    case 4:
        *out = 1;
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_stateHandler06(int obj, int p2)
{
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x54);
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 dir[3];
        struct {
            s16 angles[4];
            f32 mat[4];
        } s1;
        void *newObj;
        int setup;
        inner->unkBB6 &= ~8;
        *(s16 *)((char *)q + 0x60) = *(s16 *)((char *)q + 0x60) | 0x200;
        ObjAnim_SetCurrentMove(obj, 0xd, lbl_803E83A4, 0);
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E83B8;
        if (Obj_IsLoadingLocked() == 0) {
            return 0;
        }
        Sfx_PlayFromObject(obj, SFXtr_cnflyby6);
        setup = Obj_AllocObjectSetup(0x18, 0x42a);
        *(u8 *)((char *)setup + 6) = 0xff;
        *(u8 *)((char *)setup + 7) = 0xff;
        *(u8 *)((char *)setup + 4) = 2;
        *(u8 *)((char *)setup + 5) = 1;
        *(f32 *)((char *)setup + 8) = inner->unkAE8;
        *(f32 *)((char *)setup + 0xc) = inner->unkAEC;
        *(f32 *)((char *)setup + 0x10) = inner->unkAF0;
        newObj = (void *)Obj_SetupObject(setup, 5, -1, -1, 0);
        if (newObj != NULL) {
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
            vecRotateZXY(s1.angles, dir);
            *(f32 *)((char *)newObj + 0x24) = dir[0];
            *(f32 *)((char *)newObj + 0x28) = dir[1];
            *(f32 *)((char *)newObj + 0x2c) = dir[2];
            *(int *)((char *)newObj + 0xf4) = 0xb4;
            *(int *)((char *)newObj + 0xf8) = obj;
            *(s16 *)((char *)newObj + 0x4) = 0;
            *(s16 *)((char *)newObj + 0x2) = 0;
            *(s16 *)((char *)newObj + 0) = 0;
            (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))((int)newObj, 0x66, 0, 2, -1, 0);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_hitDetect(int obj)
{
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    int r;
    s16 *hits[4];
    s16 diff;
    if (inner->unkBB0 != 0 && *(s16 *)((char *)obj + 0xa0) != 0xf &&
        (r = ObjHits_GetPriorityHit(obj, hits, 0, 0)) != 0 && r != 0xf &&
        inner->unkBB2 == 2) {
        diff = *(s16 *)((char *)obj + 0) - (u16)*hits[0];
        if (diff > 0x8000) {
            diff = diff - 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        if (diff > 0x4000 || diff < -0x4000) {
            ((ByteFlags *)&inner->flagsBC0)->b40 = 0;
        } else {
            ((ByteFlags *)&inner->flagsBC0)->b40 = 1;
        }
        inner->unkBB0 -= 1;
        if (inner->unkBB0 <= 0) {
            (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(5, obj, -1);
            inner->unkBB0 = 1;
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, (int)inner, 7);
        }
        Sfx_PlayFromObject(obj, 0x11f);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_802C11BC(int obj, int p2, f32 f)
{
    CloudRunnerState *inner;
    int flag;
    int slot;
    if (p2 != -1) {
        flag = (((framesThisStep - 1) - p2) == 0);
    } else {
        flag = 1;
    }
    slot = (int)Camera_GetCurrentViewSlot();
    inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    inner->baddie.hitPoints = 0;
    *(int *)&inner->baddie &= ~0x8000;
    *(int *)&inner->baddie |= 0x200000;
    if (inner->unkBB2 == 2) {
        inner->baddie.unk290 = (f32)(s8)padGetStickX(0);
        inner->baddie.unk28C = (f32)(s8)padGetStickY(0);
        *(int *)&inner->baddie.unk31C = getButtonsJustPressed(0);
        *(int *)&inner->baddie.unk318 = getButtonsHeld(0);
        inner->baddie.unk330 = *(s16 *)slot;
        if (((ByteFlags *)&inner->flagsBC0)->b01 != 0) {
            Obj_UpdateRomCurveFollowVelocity(obj, (int)((char *)inner + 0x35c), inner->unkB50, lbl_803E83B4, lbl_803E8414, 1);
        }
    } else {
        f32 v = lbl_803E83A4;
        inner->baddie.unk290 = v;
        inner->baddie.unk28C = v;
        *(int *)&inner->baddie.unk31C = 0;
        *(int *)&inner->baddie.unk318 = 0;
        inner->baddie.unk330 = 0;
    }
    *(int *)&inner->baddie |= 0x400000;
    if (flag != 0) {
        *(int *)&inner->baddie &= ~0x400000;
    }
    (*(void (*)(int, int, f32, f32, int, void *))(*(int *)(*gPlayerInterface + 0x8)))(obj, (int)inner, f, timeDelta, (int)gDRCloudRunnerStateHandlers, &gDRCloudRunnerDefaultStateHandler);
    if ((*(int *)&inner->baddie.eventFlags & 1) != 0) {
        fn_802BF4D8(obj);
    }
    if (((ByteFlags *)&inner->flagsBC0)->b02 != 0) {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(inner->unkBB0 - lbl_803DE4D8);
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
        ((ObjAnimComponent *)obj)->modelInstance->flags |= 0x200000;
    } else {
        *(u8 *)((char *)inner + 0x25f) = 0;
        fn_802C11BC(obj, -1, timeDelta);
        ((ObjAnimComponent *)obj)->modelInstance->flags &= ~0x200000;
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
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
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
    *(f32 *)((char *)setup + 8) = inner->unkAE8;
    *(f32 *)((char *)setup + 0xc) = inner->unkAEC;
    *(f32 *)((char *)setup + 0x10) = inner->unkAF0;
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
    vecRotateZXY(s1.angles, dir);
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
int DR_CloudRunner_stateHandler04(int obj, int p2)
{
    CloudRunnerState *inner = *(CloudRunnerState **)((char *)obj + 0xb8);
    int a0;
    int a1;
    *(int *)((char *)p2 + 0) |= 0x1204000;
    *(u8 *)((char *)p2 + 0x25f) = 0;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 fz = lbl_803E83A4;
        CloudRunnerState *inner2;
        int q;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        inner2 = *(CloudRunnerState **)((char *)obj + 0xb8);
        q = *(int *)((char *)obj + 0x4c);
        ((ByteFlags *)&inner2->flagsBC0)->b02 = 1;
        (*(void (*)(int, int))(*(int *)(*gGameUIInterface + 0x58)))(*(s16 *)((char *)q + 0x1a), 0x5de);
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(inner2->unkBB0);
        *(s16 *)((char *)p2 + 0x338) = 0;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E83F4;
        *(f32 *)((char *)p2 + 0x2b8) = lbl_803E83F8;
        ObjAnim_SetCurrentMove(obj, 1, lbl_803E83A4, 0);
        ((ByteFlags *)&inner->flagsBC0)->b01 = 1;
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
    *(f32 *)((char *)obj + 0xc) = inner->unk3C4;
    *(f32 *)((char *)obj + 0x10) = inner->unk3C8;
    *(f32 *)((char *)obj + 0x14) = inner->unk3CC;
    a0 = (u16)getAngle(-inner->unk3D0, -inner->unk3D8);
    a1 = (u16)getAngle(inner->unk3D4,
                       sqrtf(inner->unk3D0 * inner->unk3D0 +
                             inner->unk3D8 * inner->unk3D8));
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
