#include "main/dll/DR/DRCloudball.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"

typedef struct SpscarabPlacement {
    u8 pad0[0x19 - 0x0];
    s8 unk19;
    u8 pad1A[0x20 - 0x1A];
} SpscarabPlacement;


typedef struct SpscarabState {
    f32 unk0;
    f32 unk4;
    s32 unk8;
    s16 sfxId;
    s16 mode;
    s16 unk10;
    u8 pad12[0x18 - 0x12];
} SpscarabState;


extern f32 sqrtf(f32 x);
extern f32 mathCosf(double x);
extern f32 mathSinf(double x); /* cos-like */
extern int randomGetRange(int lo, int hi);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern int Obj_GetActiveModel(int obj);
extern int Obj_GetPlayerObject(void);
extern s16 getAngle(f32 dx, f32 dz);
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(int normal, int velocity, int out);
extern f32 getXZDistance(int *p1, int *p2);
extern void itemPickupDoParticleFx(int obj, f32 a, int b, int c);
extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5, int p6, f32 f2, int p7, int p8);

extern f32 timeDelta;
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
extern f64 lbl_803E5A98; /* int->float magic 0x4330000000000000 */

extern void spscarab_hitDetect(void);
extern void spscarab_render(void);
extern void spscarab_free(int x);
extern int spscarab_getObjectTypeId(void);
extern int spscarab_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: spscarab_update
 * EN v1.0 Address: 0x801E8EE0
 * EN v1.0 Size: 588b
 */
void spscarab_update(int param_1)
{
    int p_b8;
    int p_4c;
    s16 angle;
    f32 distance;
    f32 phase;        /* sp+0x10 */
    f32 outV[3];      /* sp+0x14 (output of Vec3_ReflectAgainstNormal) */
    f32 hit_buf[24];  /* sp+0x20 .. sp+0x80 (collision struct, objBboxFn_800640cc out) */

    p_b8 = *(int *)&((GameObject *)param_1)->extra;
    p_4c = *(int *)&((GameObject *)param_1)->anim.placementData;

    if (((GameObject *)param_1)->anim.localPosY > ((SpscarabState *)p_b8)->unk0) {
        ((GameObject *)param_1)->anim.velocityY = ((GameObject *)param_1)->anim.velocityY - lbl_803E5A74 * timeDelta;
    }

    objMove(param_1,
                timeDelta * (((GameObject *)param_1)->anim.velocityX * ((SpscarabState *)p_b8)->unk4),
                ((GameObject *)param_1)->anim.velocityY * timeDelta,
                timeDelta * (((GameObject *)param_1)->anim.velocityZ * ((SpscarabState *)p_b8)->unk4));

    distance = sqrtf(((GameObject *)param_1)->anim.velocityX * ((GameObject *)param_1)->anim.velocityX +
                     ((GameObject *)param_1)->anim.velocityZ * ((GameObject *)param_1)->anim.velocityZ);

    ObjAnim_SampleRootCurvePhase(distance, (ObjAnimComponent *)param_1, &phase);
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(param_1, phase, timeDelta, 0);

    if (((GameObject *)param_1)->anim.localPosY < ((SpscarabState *)p_b8)->unk0) {
        ((GameObject *)param_1)->anim.localPosY = ((SpscarabState *)p_b8)->unk0;
        ((GameObject *)param_1)->anim.velocityY = lbl_803E5A78;
    }

    if (objBboxFn_800640cc(param_1 + 0x80, param_1 + 0xc,
                    lbl_803E5A7C, 0, (int)&hit_buf[0] /* sp+0x20 */, param_1,
                    8, -1, 0xff, 0xa) != 0) {
        Vec3_ReflectAgainstNormal((int)&hit_buf[7] /* sp+0x3c */, param_1 + 0x24, (int)outV);
        ((GameObject *)param_1)->anim.velocityX = outV[0];
        ((GameObject *)param_1)->anim.velocityZ = outV[2];
        angle = (s16)getAngle(-((GameObject *)param_1)->anim.velocityX, -((GameObject *)param_1)->anim.velocityZ);
        *(s16 *)(param_1) = angle;
    }

    if (getXZDistance((int *)(Obj_GetPlayerObject() + 0x18), (int *)&((GameObject *)param_1)->anim.worldPosX)
        < lbl_803E5A80) {
        Sfx_PlayFromObject(param_1, (u16)((SpscarabState *)p_b8)->sfxId);
        itemPickupDoParticleFx(param_1, lbl_803E5A84, ((SpscarabState *)p_b8)->mode, 0x28);
        ((GameObject *)param_1)->objectFlags = ((GameObject *)param_1)->objectFlags | 0x8000;
        ((GameObject *)param_1)->anim.flags = ((GameObject *)param_1)->anim.flags | 0x4000;

        {
            int r5val = (((SpscarabPlacement *)p_4c)->unk19 == 0) ? 1 : 0;
            int v3 = ((SpscarabState *)p_b8)->unk8;
            int r4val = (((SpscarabPlacement *)p_4c)->unk19 == 0) ? 0 : 1;
            (*(void (**)(int, int, int))(*(int *)(*(int *)(v3 + 0x68)) + 0x50))(
                v3, r4val, r5val);
        }
    }

    if ((((GameObject *)param_1)->objectFlags & 0x800) != 0) {
        if (((SpscarabState *)p_b8)->unk10 != 0) {
            objfx_spawnDirectionalBurst(param_1, 5, lbl_803E5A84, (u8)((SpscarabState *)p_b8)->unk10, 1, 0x14,
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
void spscarab_init(int param_1, int param_2)
{
    ObjAnimComponent *objAnim;
    int p_b8;
    int model;
    struct { u16 a; u8 b; } pair;

    objAnim = (ObjAnimComponent *)param_1;
    p_b8 = *(int *)&((GameObject *)param_1)->extra;
    pair.a = lbl_803E5A70;
    pair.b = lbl_803E5A72;

    ((GameObject *)param_1)->objectFlags = ((GameObject *)param_1)->objectFlags | 0x6000;
    *(s16 *)(param_1) = (s16)((s32)(s8)*(u8 *)(param_2 + 0x18) << 8);

    ((GameObject *)param_1)->anim.velocityX =
        -mathSinf(lbl_803E5A8C * (f32)(s32)*(s16 *)(param_1) /
                     lbl_803E5A90);
    ((GameObject *)param_1)->anim.velocityZ =
        -mathCosf(lbl_803E5A8C * (f32)(s32)*(s16 *)(param_1) /
             lbl_803E5A90);

    objAnim->bankIndex = (s8)(1 - *(u8 *)(param_2 + 0x19));

    ((SpscarabState *)p_b8)->unk0 = (f32)(s32)*(s16 *)(param_2 + 0x1a);
    ((SpscarabState *)p_b8)->unk4 = lbl_803E5A94 + (f32)randomGetRange(0, 0x64) / lbl_803E5A80;
    ((SpscarabState *)p_b8)->unk8 = *(int *)(param_2 + 0x14);
    *(int *)(param_2 + 0x14) = -1;

    Sfx_AddLoopedObjectSound(param_1, 0x406);
    model = Obj_GetActiveModel(param_1);

    switch ((s8)*(u8 *)(param_2 + 0x19)) {
    case 0:
        *(u8 *)(*(int *)(model + 0x34) + 8) = *((u8 *)&pair + randomGetRange(0, 2));
        ((SpscarabState *)p_b8)->sfxId = 0x41;
        ((SpscarabState *)p_b8)->mode = 4;
        ((SpscarabState *)p_b8)->unk10 = 2;
        break;
    case 1:
        ((SpscarabState *)p_b8)->sfxId = 0x42;
        ((SpscarabState *)p_b8)->mode = 1;
        ((SpscarabState *)p_b8)->unk10 = 0;
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
int spdrape_getExtraSize(void)
{
    return 0x18;
}

/*
 * --INFO--
 *
 * Function: spdrape_getObjectTypeId
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */
int spdrape_getObjectTypeId(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */
void spdrape_free(void)
{
}

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */
void spdrape_render(void)
{
}

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */
void spdrape_hitDetect(void)
{
}
