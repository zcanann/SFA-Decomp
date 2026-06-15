/* DLL 0x287 — SP scarab / shop item / shopkeeper objects [801E8EA4-801E8EE0) */
#include "main/effect_interfaces.h"
#include "main/dll/shopkeeperstate_struct.h"
#include "main/dll/pushcartstate97_types.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);

STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

extern void Stack_Free();

extern void Sfx_RemoveLoopedObjectSound(int x, int y);
extern f32 lbl_803E5A30;
extern f32 timeDelta;
extern void gameTextShow(int);
extern void characterDoEyeAnims(int obj, int p2);
extern f32 sqrtf(f32 x);
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 radius, int c, int d, int e, f32 scale, int g, int h);
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

void spscarab_render(void)
{
}

void spscarab_hitDetect(void)
{
}

int shopkeeper_getExtraSize(void);
int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_getObjectTypeId(void) { return 0x0; }

void spscarab_free(int x) { Sfx_RemoveLoopedObjectSound(x, 0x406); }

/* segment pragma-stack balance (re-split): */

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
        ((GameObject*)obj)->anim.rotX = angle;
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

void spscarab_init(int obj, int def)
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
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(s8) * (u8*)(def + 0x18) << 8);

    ((GameObject*)obj)->anim.velocityX =
        -mathSinf(lbl_803E5A8C * (f32)(s32)((GameObject*)obj)->anim.rotX /
            lbl_803E5A90);
    ((GameObject*)obj)->anim.velocityZ =
        -mathCosf(lbl_803E5A8C * (f32)(s32)((GameObject*)obj)->anim.rotX /
            lbl_803E5A90);

    objAnim->bankIndex = (s8)(1 - *(u8*)(def + 0x19));

    ((SpscarabState*)p_b8)->unk0 = (f32)(s32) * (s16*)(def + 0x1a);
    ((SpscarabState*)p_b8)->unk4 = lbl_803E5A94 + (f32)randomGetRange(0, 0x64) / lbl_803E5A80;
    ((SpscarabState*)p_b8)->unk8 = *(int*)(def + 0x14);
    *(int*)(def + 0x14) = -1;

    Sfx_AddLoopedObjectSound(obj, 0x406);
    model = Obj_GetActiveModel(obj);

    switch ((s8) * (u8*)(def + 0x19))
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

void spscarab_release(void)
{
}

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
