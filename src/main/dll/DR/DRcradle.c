#include "main/dll/DR/DRcradle.h"
#include "main/dll/path_control_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objhits_types.h"

typedef struct SnowBikeMountState {
    s16 unk0;
    u8 pad2[0xC - 0x2];
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x3D3 - 0x18];
    s8 unk3D3;
    u8 pad3D4[0x3E8 - 0x3D4];
    f32 unk3E8;
    f32 unk3EC;
    f32 unk3F0;
    u8 pad3F4[0x400 - 0x3F4];
    f32 unk400;
    f32 unk404;
    f32 unk408;
    u8 pad40C[0x414 - 0x40C];
    f32 unk414;
    u8 pad418[0x420 - 0x418];
    u8 unk420;
    u8 pad421[0x428 - 0x421];
    u8 unk428;
    u8 pad429[0x434 - 0x429];
    u8 unk434;
    u8 unk435;
    u8 pad436[0x494 - 0x436];
    f32 unk494;
    f32 unk498;
    f32 unk49C;
} SnowBikeMountState;


typedef struct SnowBikeSetTypeState {
    s16 unk0;
    u8 pad2[0xC - 0x2];
    f32 unkC;
    f32 unk10;
    f32 unk14;
    u8 pad18[0x3D3 - 0x18];
    s8 unk3D3;
    u8 pad3D4[0x3E8 - 0x3D4];
    f32 unk3E8;
    f32 unk3EC;
    f32 unk3F0;
    u8 pad3F4[0x400 - 0x3F4];
    f32 unk400;
    f32 unk404;
    f32 unk408;
    u8 pad40C[0x414 - 0x40C];
    f32 unk414;
    u8 pad418[0x420 - 0x418];
    u8 unk420;
    s8 unk421;
    u8 pad422[0x428 - 0x422];
    u8 unk428;
    u8 pad429[0x434 - 0x429];
    u8 unk434;
    u8 unk435;
    u8 pad436[0x448 - 0x436];
    s16 unk448;
    u8 pad44A[0x494 - 0x44A];
    f32 unk494;
    f32 unk498;
    f32 unk49C;
    u8 pad4A0[0x4B8 - 0x4A0];
    f32 unk4B8;
    f32 unk4BC;
    f32 unk4C0;
    u8 pad4C4[0x4C8 - 0x4C4];
} SnowBikeSetTypeState;




/* Trivial 4b 0-arg blr leaves. */
void SnowBike_func17(void) {}
void SnowBike_func16(void) {}

/* 8b "li r3, N; blr" returners. */
int SnowBike_func0E(void) { return 0x2; }
int SnowBike_render2(void) { return 0x0; }
int SnowBike_getExtraSize(void) { return 0x59c; }
int SnowBike_getObjectTypeId(void) { return 0x3; }

/* Pattern wrappers. */
u8 SnowBike_func0B(int *obj) { return *(u8*)((char*)((int**)obj)[0xb8/4] + 0x420); }

/*
 * --INFO--
 *
 * Function: SnowBike_mount
 * EN v1.0 Address: 0x801ECD98
 * EN v1.0 Size: 56b
 */
void SnowBike_mount(int obj, f32 *x, f32 *y, f32 *z)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    ((SnowBikeMountState *)t)->unk400 = ((GameObject *)obj)->anim.localPosX;
    ((SnowBikeMountState *)t)->unk404 = ((GameObject *)obj)->anim.localPosY;
    ((SnowBikeMountState *)t)->unk408 = ((GameObject *)obj)->anim.localPosZ;
    *x = ((SnowBikeMountState *)t)->unk400;
    *y = ((SnowBikeMountState *)t)->unk404;
    *z = ((SnowBikeMountState *)t)->unk408;
}

/*
 * --INFO--
 *
 * Function: SnowBike_modelMtxFn
 * EN v1.0 Address: 0x801ECDE0
 * EN v1.0 Size: 32b
 */
void SnowBike_modelMtxFn(int obj, f32 *x, f32 *y, f32 *z)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    *x = *(f32 *)(t + 0x3e8);
    *y = *(f32 *)(t + 0x3ec);
    *z = *(f32 *)(t + 0x3f0);
}

extern void ObjGroup_RemoveObject(int obj, int group);
extern void mm_free(void *p);
extern void *gCheckpointInterface;
extern int lbl_803DC0BC;
extern f32 sqrtf(f32 x);
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B8C;
extern f32 lbl_803E5BB0;
extern f32 lbl_803E5BB8;
extern f32 lbl_803E5BA8;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BFC;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C14;
extern f32 lbl_803E5C34;
extern f32 lbl_803E5C38;
extern f32 lbl_803E5C3C;
extern f32 lbl_803E5C40;
extern f32 lbl_803E5C44;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5B70;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern int GameBit_Set(int bit, int val);
extern void *mapRomListFindItem(int a, int b, int c, int d, int e);
extern int lbl_80328590[];

/*
 * --INFO--
 *
 * Function: SnowBike_func15
 * EN v1.0 Address: 0x801ECA64
 * EN v1.0 Size: 352b
 */
void SnowBike_func15(int obj)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    int *table;
    void *found;
    f32 zero;

    table = (int *)((int)lbl_80328590 + (int)(*(u8 *)(t + 0x434)) * 12);
    found = mapRomListFindItem(table[*(u8 *)(t + 0x435)], 0, 0, 0, 0);
    if (found != NULL) {
        if (*(u8 *)(t + 0x434) != 0) {
            ((GameObject *)obj)->anim.localPosX = *(f32 *)((char *)found + 0x8);
            ((GameObject *)obj)->anim.localPosY = *(f32 *)((char *)found + 0xc);
            ((GameObject *)obj)->anim.localPosZ = *(f32 *)((char *)found + 0x10);
            ((GameObject *)obj)->anim.rotX = (s16)((*(u8 *)((char *)found + 0x29)) << 8);
        }
        (*(void (**)(int, int, int))((char *)*(int *)gCheckpointInterface + 0x10))(obj, t + 0x28, 0);
        *(f32 *)(t + 0xc) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(t + 0x10) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(t + 0x14) = ((GameObject *)obj)->anim.localPosZ;
        *(s16 *)(t + 0x0) = ((GameObject *)obj)->anim.rotX;
        zero = lbl_803E5AE8;
        *(f32 *)(t + 0x494) = zero;
        *(f32 *)(t + 0x498) = zero;
        *(f32 *)(t + 0x49c) = zero;
        (*gPathControlInterface)->attachObject((void *)obj, (void *)(t + 0x178));
        {
            ObjHitsPriorityState *hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
            hitState->localPosX = ((GameObject *)obj)->anim.localPosX;
            hitState->localPosY = ((GameObject *)obj)->anim.localPosY;
            hitState->localPosZ = ((GameObject *)obj)->anim.localPosZ;
            hitState->worldPosX = ((GameObject *)obj)->anim.worldPosX;
            hitState->worldPosY = ((GameObject *)obj)->anim.worldPosY;
            hitState->worldPosZ = ((GameObject *)obj)->anim.worldPosZ;
        }
        *(s8 *)(t + 0x3d3) = 1;
    }
}

extern void setMatrixFromObjectPos(void *mtx, s16 *vec);
extern void mtxRotateByVec3s(void *mtx, s16 *vec);

typedef struct SnowBikeFlags {
    u8 resetLatch : 1;      /* 0x80 */
    u8 pathActive : 1;      /* 0x40 */
    u8 uiPrompt : 1;        /* 0x20 */
    u8 impulseLatch : 1;    /* 0x10 */
    u8 flags : 4;
} SnowBikeFlags;

/*
 * --INFO--
 *
 * Function: fn_801EC7A0
 * EN v1.0 Address: 0x801EC7A0
 * EN v1.0 Size: 208b
 */
void fn_801EC7A0(int p1, int p2)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;

    v.mat[1] = lbl_803E5AE8;
    v.mat[2] = lbl_803E5AE8;
    v.mat[3] = lbl_803E5AE8;
    v.mat[0] = lbl_803E5AEC;

    v.angles[0] = *(s16 *)(p2 + 0x40e);
    v.angles[1] = 0;
    v.angles[2] = 0;
    setMatrixFromObjectPos((void *)(p2 + 0x6c), v.angles);

    v.angles[0] = -*(s16 *)(p2 + 0x40e);
    v.angles[1] = 0;
    v.angles[2] = 0;
    mtxRotateByVec3s((void *)(p2 + 0xac), v.angles);

    v.angles[0] = *(s16 *)(p2 + 0x40c);
    v.angles[1] = 0;
    v.angles[2] = 0;
    setMatrixFromObjectPos((void *)(p2 + 0xec), v.angles);

    v.angles[0] = -*(s16 *)(p2 + 0x40c);
    v.angles[1] = 0;
    v.angles[2] = 0;
    mtxRotateByVec3s((void *)(p2 + 0x12c), v.angles);
}

/*
 * --INFO--
 *
 * Function: fn_801EC870
 * EN v1.0 Address: 0x801EC870
 * EN v1.0 Size: 184b
 */
#pragma dont_inline on
void fn_801EC870(int p1, register int p2_int)
{
    f32 fz, fa, fb, fc;
    SnowBikeFlags *flags;
    *(f32 *)(p2_int + 0x52c) = lbl_803E5C34;
    *(f32 *)(p2_int + 0x530) = lbl_803E5C38;
    *(f32 *)(p2_int + 0x534) = lbl_803E5BF4;
    fz = lbl_803E5AE8;
    *(f32 *)(p2_int + 0x414) = fz;
    *(f32 *)(p2_int + 0x584) = fz;
    *(f32 *)(p2_int + 0x548) = lbl_803E5BFC;
    *(f32 *)(p2_int + 0x54c) = lbl_803E5BE4;
    *(f32 *)(p2_int + 0x540) = lbl_803E5B20;
    *(f32 *)(p2_int + 0x544) = lbl_803E5AF8;
    *(f32 *)(p2_int + 0x558) = lbl_803E5BA8;
    *(f32 *)(p2_int + 0x56c) = lbl_803E5C00;
    flags = (SnowBikeFlags *)(p2_int + 0x428);
    flags->resetLatch = 0;
    *(f32 *)(p2_int + 0x430) = fz;
    fa = *(f32 *)(p2_int + 0x470);
    *(f32 *)(p2_int + 0x464) = fa;
    *(f32 *)(p2_int + 0x47c) = fa;
    fb = *(f32 *)(p2_int + 0x474);
    *(f32 *)(p2_int + 0x468) = fb;
    *(f32 *)(p2_int + 0x480) = fb;
    fc = *(f32 *)(p2_int + 0x478);
    *(f32 *)(p2_int + 0x46c) = fc;
    *(f32 *)(p2_int + 0x484) = fc;
    flags->pathActive = 0;
    flags->impulseLatch = 0;
    *(u32 *)(p2_int + 0x42c) = 0;
    *(f32 *)(p2_int + 0x3e4) = fz;
    *(f32 *)(p2_int + 0x3e0) = lbl_803E5AEC;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: fn_801EC928
 * EN v1.0 Address: 0x801EC928
 * EN v1.0 Size: 148b
 */
void fn_801EC928(int p1, int p2)
{
    f32 fa, fz;
    *(f32 *)(p2 + 0x4b0) = lbl_803E5C3C;
    *(f32 *)(p2 + 0x530) = lbl_803E5C38;
    *(f32 *)(p2 + 0x534) = lbl_803E5BF4;
    *(f32 *)(p2 + 0x538) = lbl_803E5B74;
    *(f32 *)(p2 + 0x53c) = lbl_803E5C14;
    *(f32 *)(p2 + 0x548) = lbl_803E5BFC;
    *(f32 *)(p2 + 0x54c) = lbl_803E5BE4;
    *(f32 *)(p2 + 0x540) = lbl_803E5B20;
    *(f32 *)(p2 + 0x544) = lbl_803E5AF8;
    fa = lbl_803E5C40;
    *(f32 *)(p2 + 0x57c) = fa;
    *(f32 *)(p2 + 0x580) = fa;
    *(f32 *)(p2 + 0x554) = lbl_803E5C44;
    *(f32 *)(p2 + 0x550) = lbl_803E5C10;
    *(f32 *)(p2 + 0x570) = lbl_803E5BB8;
    fz = lbl_803E5BA8;
    *(f32 *)(p2 + 0x558) = fz;
    *(f32 *)(p2 + 0x578) = lbl_803E5B8C;
    *(f32 *)(p2 + 0x574) = lbl_803E5BB0;
    *(f32 *)(p2 + 0x56c) = lbl_803E5C00;
    *(f32 *)(p2 + 0x4ac) = fz;
}

/*
 * --INFO--
 *
 * Function: SnowBike_setType
 * EN v1.0 Address: 0x801ECC94
 * EN v1.0 Size: 244b
 */
void SnowBike_setType(int obj, int type)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    u32 bit;
    ((SnowBikeSetTypeState *)t)->unk421 = (s8)type;
    if (type == 2) {
        GameBit_Set(((SnowBikeSetTypeState *)t)->unk448, 1);
        fn_801EC870(obj, t);
        bit = (((SnowBikeSetTypeState *)t)->unk428 >> 5) & 1;
        if (bit != 0) {
            ((SnowBikeSetTypeState *)t)->unk4B8 = lbl_803E5B90;
            ((SnowBikeSetTypeState *)t)->unk4C0 = lbl_803E5AEC;
            ((SnowBikeSetTypeState *)t)->unk4BC = lbl_803E5B94;
            if (((SnowBikeSetTypeState *)t)->unk421 == 2) {
                (*gGameUIInterface)->initAirMeter((int)((SnowBikeSetTypeState *)t)->unk4B8, 0x5cd);
                (*gGameUIInterface)->airMeterSetRatio(lbl_803E5B98);
            }
        }
        if (((GameObject *)obj)->anim.seqId == 0x72) {
            ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->lateralResponseWeight = 0x14;
            ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->axialResponseWeight = 0x14;
        }
    }
}

/*
 * --INFO--
 *
 * Function: SnowBike_func12
 * EN v1.0 Address: 0x801ECC38
 * EN v1.0 Size: 92b
 */
void SnowBike_func12(int obj, f32 *outFloat, s32 *outBool)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    f32 v, r;
    *outFloat = *(f32 *)(t + 0x414) / lbl_803E5C48;
    v = *outFloat;
    *outFloat = (v < lbl_803E5B70) ? lbl_803E5B70 : ((v > lbl_803E5AEC) ? lbl_803E5AEC : v);
    *outBool = *(f32 *)(t + 0x414) < lbl_803E5AE8;
}

/*
 * --INFO--
 *
 * Function: SnowBike_func13
 * EN v1.0 Address: 0x801ECBD4
 * EN v1.0 Size: 100b
 */
f32 SnowBike_func13(int obj, f32 *out)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    f32 r;
    *out = lbl_803E5BB8;
    r = sqrtf(*(f32 *)(t + 0x49c) * *(f32 *)(t + 0x49c)
            + (*(f32 *)(t + 0x494) * *(f32 *)(t + 0x494)
             + *(f32 *)(t + 0x498) * *(f32 *)(t + 0x498)));
    r = r * lbl_803E5BA8;
    if (r > lbl_803E5AEC) {
        r = lbl_803E5AEC;
    }
    return r;
}

/*
 * --INFO--
 *
 * Function: SnowBike_setScale
 * EN v1.0 Address: 0x801ECE0C
 * EN v1.0 Size: 36b
 */
u32 SnowBike_setScale(int obj)
{
    int t = *(int *)&((GameObject *)obj)->extra;
    u32 bit = (*(u8 *)(t + 0x428) >> 1) & 1;
    if (bit != 0) {
        return 0;
    }
    return *(u8 *)(t + 0x420);
}

/*
 * --INFO--
 *
 * Function: fn_801EC9BC
 * EN v1.0 Address: 0x801EC9BC
 * EN v1.0 Size: 56b
 */
void fn_801EC9BC(int obj)
{
    (*(void (**)(int))((char *)*(int *)gCheckpointInterface + 0x34))(*(int *)&((GameObject *)obj)->extra + 0x28);
}

/*
 * --INFO--
 *
 * Function: fn_801EC9F4
 * EN v1.0 Address: 0x801EC9F4
 * EN v1.0 Size: 104b
 */
u32 fn_801EC9F4(int obj)
{
    int result = (*(int (**)(int))((char *)*(int *)gCheckpointInterface + 0x34))(*(int *)&((GameObject *)obj)->extra + 0x28);
    if (result == 3) {
        if (lbl_803DC0BC == -1) {
            return 1;
        }
    }
    return (u32)__cntlzw(lbl_803DC0BC - 1 - result) >> 5;
}

/*
 * --INFO--
 *
 * Function: SnowBike_free
 * EN v1.0 Address: 0x801ECE40
 * EN v1.0 Size: 132b
 */
void SnowBike_free(int obj)
{
    char *p;
    int i;
    u32 bit;
    int t;

    t = *(int *)&((GameObject *)obj)->extra;
    ObjGroup_RemoveObject(obj, 0xa);
    i = 0;
    p = (char *)t;
    for (; i < 9; i++) {
        mm_free(*(void **)(p + 0x4c8));
        p += 8;
    }
    bit = (*(u8 *)(t + 0x428) >> 5) & 1;
    if (bit != 0) {
        (*gGameUIInterface)->airMeterSetShutdown();
    }
}

/* 16b chained patterns. */
s32 SnowBike_func14(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x422); }
s32 SnowBike_getType(int *obj) { return *(s8*)((char*)((int**)obj)[0xb8/4] + 0x421); }
