/* === moved from main/dll/DR/DRpushcart.c [801E8EA4-801E8EE0) (TU re-split, docs/boundary_audit.md) === */
#include "main/effect_interfaces.h"
#include "main/dll/shopkeeperstate_struct.h"
#include "main/dll/pushcartstate97_types.h"
#include "main/objseq.h"
#include "main/screen_transition.h"





/* shopitem_getExtraSize == 0xec (spline-following pushcart item). */


STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

/* shopkeeper_getExtraSize == 0x9d8. */


STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);




/*
 * --INFO--
 *
 * Function: FUN_801e76a0
 * EN v1.0 Address: 0x801E76A0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801E7714
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e7be4
 * EN v1.0 Address: 0x801E7BE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E7C90
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e7be8
 * EN v1.0 Address: 0x801E7BE8
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x801E823C
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: FUN_801e7d3c
 * EN v1.0 Address: 0x801E7D3C
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x801E83B8
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E7FEC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E85B4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Stack_Free();

#pragma scheduling off
#pragma peephole off

/*
 * --INFO--
 *
 * Function: shopkeeper_render
 * EN v1.0 Address: 0x801E8014
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E85DC
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801e80b0
 * EN v1.0 Address: 0x801E80B0
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x801E8680
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e8274
 * EN v1.0 Address: 0x801E8274
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E87C4
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e8300
 * EN v1.0 Address: 0x801E8300
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801E89A0
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e85b0
 * EN v1.0 Address: 0x801E85B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801E8CE4
 * EN v1.1 Size: 452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801e85b8
 * EN v1.0 Address: 0x801E85B8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801E8EA8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off


/* Trivial 4b 0-arg blr leaves. */





void spscarab_render(void)
{
}

void spscarab_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int shopkeeper_getExtraSize(void);
int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_getObjectTypeId(void) { return 0x0; }

extern void Sfx_RemoveLoopedObjectSound(int x, int y);
void spscarab_free(int x) { Sfx_RemoveLoopedObjectSound(x, 0x406); }

extern f32 lbl_803E5A30;







extern f32 timeDelta;
extern void gameTextShow(int);
extern void characterDoEyeAnims(int obj, int p2);














extern f32 sqrtf(f32 x);


extern void objfx_spawnDirectionalBurst(int obj, int a, f32 radius, int c, int d, int e, f32 scale, int g, int h);




/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"

typedef struct SpscarabPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 unk19;
    u8 pad1A[0x20 - 0x1A];
} SpscarabPlacement;


typedef struct SpscarabState
{
    f32 unk0;
    f32 unk4;
    s32 unk8;
    s16 sfxId;
    s16 mode;
    s16 unk10;
    u8 pad12[0x18 - 0x12];
} SpscarabState;


extern f32 mathCosf(double x);
extern f32 mathSinf(double x); /* cos-like */
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern s16 getAngle(f32 dx, f32 dz);
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(int normal, int velocity, int out);
extern f32 getXZDistance(int* p1, int* p2);
extern void itemPickupDoParticleFx(int obj, f32 a, int b, int c);
extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5, int p6, f32 f2, int p7, int p8);

extern u16 lbl_803E5A70;
extern u8 lbl_803E5A72;
extern f32 lbl_803E5A74;
extern f32 lbl_803E5A78;
extern f32 lbl_803E5A7C;
extern f32 lbl_803E5A80;
extern f32 lbl_803E5A84;
extern f32 lbl_803E5A88;
extern f32 lbl_803E5A8C;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5A94;


/*
 * --INFO--
 *
 * Function: spscarab_update
 * EN v1.0 Address: 0x801E8EE0
 * EN v1.0 Size: 588b
 */
void spscarab_update(int obj)
{
    extern int Obj_GetPlayerObject(void); /* #57 */
    int state;
    int placement;
    s16 angle;
    f32 distance;
    f32 phase; /* sp+0x10 */
    f32 outV[3]; /* sp+0x14 (output of Vec3_ReflectAgainstNormal) */
    f32 hit_buf[24]; /* sp+0x20 .. sp+0x80 (collision struct, objBboxFn_800640cc out) */

    state = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->anim.localPosY > ((SpscarabState*)state)->unk0)
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E5A74 * timeDelta;
    }

    objMove(obj,
            timeDelta * (((GameObject*)obj)->anim.velocityX * ((SpscarabState*)state)->unk4),
            ((GameObject*)obj)->anim.velocityY * timeDelta,
            timeDelta * (((GameObject*)obj)->anim.velocityZ * ((SpscarabState*)state)->unk4));

    distance = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
        ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);

    ObjAnim_SampleRootCurvePhase(distance, (ObjAnimComponent*)obj, &phase);
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, phase, timeDelta, 0);

    if (((GameObject*)obj)->anim.localPosY < ((SpscarabState*)state)->unk0)
    {
        ((GameObject*)obj)->anim.localPosY = ((SpscarabState*)state)->unk0;
        ((GameObject*)obj)->anim.velocityY = lbl_803E5A78;
    }

    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc,
                           lbl_803E5A7C, 0, (int)&hit_buf[0] /* sp+0x20 */, obj,
                           8, -1, 0xff, 0xa) != 0)
    {
        Vec3_ReflectAgainstNormal((int)&hit_buf[7] /* sp+0x3c */, obj + 0x24, (int)outV);
        ((GameObject*)obj)->anim.velocityX = outV[0];
        ((GameObject*)obj)->anim.velocityZ = outV[2];
        angle = (s16)getAngle(-((GameObject*)obj)->anim.velocityX, -((GameObject*)obj)->anim.velocityZ);
        *(s16*)(obj) = angle;
    }

    if (getXZDistance((int*)(Obj_GetPlayerObject() + 0x18), (int*)&((GameObject*)obj)->anim.worldPosX)
        < lbl_803E5A80)
    {
        Sfx_PlayFromObject(obj, (u16)((SpscarabState*)state)->sfxId);
        itemPickupDoParticleFx(obj, lbl_803E5A84, ((SpscarabState*)state)->mode, 0x28);
        ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x8000;
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | 0x4000;

        {
            int r5val = (((SpscarabPlacement*)placement)->unk19 == 0) ? 1 : 0;
            int v3 = ((SpscarabState*)state)->unk8;
            int r4val = (((SpscarabPlacement*)placement)->unk19 == 0) ? 0 : 1;
            (*(void (**)(int, int, int))(*(int*)(*(int*)(v3 + 0x68)) + 0x50))(
                v3, r4val, r5val);
        }
    }

    if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        if (((SpscarabState*)state)->unk10 != 0)
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A84, (u8)((SpscarabState*)state)->unk10, 1, 0x14,
                                        lbl_803E5A88, 0, 0);
        }
    }
}

/*
 * --INFO--
 *
 * Function: spscarab_init
 * EN v1.0 Address: 0x801E912C
 * EN v1.0 Size: 500b
 */
void spscarab_init(int obj, int param_2)
{
    extern int Obj_GetActiveModel(int obj); /* #57 */
    extern int randomGetRange(int lo, int hi); /* #57 */
    ObjAnimComponent* objAnim;
    int p_b8;
    int model;
    struct
    {
        u16 a;
        u8 b;
    } pair;

    objAnim = (ObjAnimComponent*)obj;
    p_b8 = *(int*)&((GameObject*)obj)->extra;
    pair.a = lbl_803E5A70;
    pair.b = lbl_803E5A72;

    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x6000;
    *(s16*)(obj) = (s16)((s32)(s8) * (u8*)(param_2 + 0x18) << 8);

    ((GameObject*)obj)->anim.velocityX =
        -mathSinf(lbl_803E5A8C * (f32)(s32) * (s16*)(obj) /
            lbl_803E5A90);
    ((GameObject*)obj)->anim.velocityZ =
        -mathCosf(lbl_803E5A8C * (f32)(s32) * (s16*)(obj) /
            lbl_803E5A90);

    objAnim->bankIndex = (s8)(1 - *(u8*)(param_2 + 0x19));

    ((SpscarabState*)p_b8)->unk0 = (f32)(s32) * (s16*)(param_2 + 0x1a);
    ((SpscarabState*)p_b8)->unk4 = lbl_803E5A94 + (f32)randomGetRange(0, 0x64) / lbl_803E5A80;
    ((SpscarabState*)p_b8)->unk8 = *(int*)(param_2 + 0x14);
    *(int*)(param_2 + 0x14) = -1;

    Sfx_AddLoopedObjectSound(obj, 0x406);
    model = Obj_GetActiveModel(obj);

    switch ((s8) * (u8*)(param_2 + 0x19))
    {
    case 0:
        *(u8*)(*(int*)(model + 0x34) + 8) = *((u8*)&pair + randomGetRange(0, 2));
        ((SpscarabState*)p_b8)->sfxId = 0x41;
        ((SpscarabState*)p_b8)->mode = 4;
        ((SpscarabState*)p_b8)->unk10 = 2;
        break;
    case 1:
        ((SpscarabState*)p_b8)->sfxId = 0x42;
        ((SpscarabState*)p_b8)->mode = 1;
        ((SpscarabState*)p_b8)->unk10 = 0;
        break;
    }
}

/*
 * --INFO--
 *
 * Function: spscarab_release
 * EN v1.0 Address: 0x801E9320
 * EN v1.0 Size: 4b
 */
void spscarab_release(void)
{
}

/*
 * --INFO--
 *
 * Function: spscarab_initialise
 * EN v1.0 Address: 0x801E9324
 * EN v1.0 Size: 4b
 */
void spscarab_initialise(void)
{
}

ObjectDescriptor gSPScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spscarab_initialise,
    (ObjectDescriptorCallback)spscarab_release,
    0,
    (ObjectDescriptorCallback)spscarab_init,
    (ObjectDescriptorCallback)spscarab_update,
    (ObjectDescriptorCallback)spscarab_hitDetect,
    (ObjectDescriptorCallback)spscarab_render,
    (ObjectDescriptorCallback)spscarab_free,
    (ObjectDescriptorCallback)spscarab_getObjectTypeId,
    spscarab_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: spdrape_getExtraSize
 * EN v1.0 Address: 0x801E9328
 * EN v1.0 Size: 8b
 */

/*
 * --INFO--
 *
 * Function: spdrape_getObjectTypeId
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */
