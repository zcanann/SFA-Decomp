/*
 * spscarab (DLL 0x287) - the scarab coin / pickup that the shopkeeper
 * scatters when paid (see spshopkeeper fn_801E7DC8, which spawns object
 * type 1151 = this object).
 *
 * Each scarab is launched along its facing angle, falls under gravity and
 * bounces off geometry (objBboxFn_800640cc + Vec3_ReflectAgainstNormal),
 * resting on a placement-supplied ground height. When the player comes
 * within pickupRadius it plays its pickup sfx, emits collection particles,
 * marks itself for despawn and notifies the owning shop object through its
 * interface vtable. Two kinds (placement->kind 0/1) differ only in sfx,
 * particle mode and the trailing dust-burst count.
 */
#include "main/dll/shopkeeperstate_struct.h"
#include "main/dll/pushcartstate97_types.h"
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/game_object.h"

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);
STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

extern void Sfx_RemoveLoopedObjectSound(int x, int y);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern f32 timeDelta;
extern f32 sqrtf(f32 x);
extern f32 mathCosf(double x);
extern f32 mathSinf(double x);
extern s16 getAngle(f32 dx, f32 dz);
extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(int normal, int velocity, int out);
extern f32 getXZDistance(int* p1, int* p2);
extern void itemPickupDoParticleFx(int obj, f32 a, int b, int c);
extern void objfx_spawnDirectionalBurst(int obj, int p2, f32 f1, int p4, int p5, int p6, f32 f2, int p7, int p8);
extern u16 lbl_803E5A70;
extern u8 lbl_803E5A72;
extern f32 lbl_803E5A74; /* gravity */
extern f32 lbl_803E5A78; /* ground-bounce velocityY */
extern f32 lbl_803E5A7C; /* bbox collision radius */
extern f32 lbl_803E5A80; /* pickup radius */
extern f32 lbl_803E5A84; /* pickup particle scale */
extern f32 lbl_803E5A88; /* dust-burst scale */
extern f32 lbl_803E5A8C;
extern f32 lbl_803E5A90;
extern f32 lbl_803E5A94; /* base horizontal speed scale */

/* init() reads the placement raw off def: rotX byte (0x18), kind (0x19),
   vendorObj (int, 0x14) and groundY (s16, 0x1a). */
typedef struct SpscarabPlacement
{
    u8 pad0[0x19 - 0x0];
    s8 kind; /* 0x19: scarab variant (0 / 1) */
    u8 pad1A[0x20 - 0x1A];
} SpscarabPlacement;

STATIC_ASSERT(sizeof(SpscarabPlacement) == 0x20);

typedef struct SpscarabState
{
    f32 groundY;    /* 0x00: rest height; gravity above it, bounce below */
    f32 speedScale; /* 0x04: randomized horizontal velocity scale */
    s32 vendorObj;  /* 0x08: owning shop object (notified on pickup) */
    s16 sfxId;      /* 0x0C: pickup sfx */
    s16 mode;       /* 0x0E: itemPickupDoParticleFx mode */
    s16 burstCount; /* 0x10: trailing dust-burst count (0 = none) */
    u8 pad12[0x14 - 0x12];
} SpscarabState;

STATIC_ASSERT(sizeof(SpscarabState) == 0x14);

void spscarab_render(void)
{
}

void spscarab_hitDetect(void)
{
}

int spscarab_getExtraSize(void) { return 0x14; }
int spscarab_getObjectTypeId(void) { return 0x0; }

void spscarab_free(int x) { Sfx_RemoveLoopedObjectSound(x, 0x406); }

void spscarab_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    int state;
    int placement;
    s16 angle;
    f32 distance;
    f32 phase;
    f32 outV[3];
    f32 hit_buf[24]; /* objBboxFn_800640cc collision output */

    state = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->anim.localPosY > ((SpscarabState*)state)->groundY)
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - lbl_803E5A74 * timeDelta;
    }

    objMove(obj,
            timeDelta * (((GameObject*)obj)->anim.velocityX * ((SpscarabState*)state)->speedScale),
            ((GameObject*)obj)->anim.velocityY * timeDelta,
            timeDelta * (((GameObject*)obj)->anim.velocityZ * ((SpscarabState*)state)->speedScale));

    distance = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
        ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);

    ObjAnim_SampleRootCurvePhase(distance, (ObjAnimComponent*)obj, &phase);
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, phase, timeDelta, 0);

    if (((GameObject*)obj)->anim.localPosY < ((SpscarabState*)state)->groundY)
    {
        ((GameObject*)obj)->anim.localPosY = ((SpscarabState*)state)->groundY;
        ((GameObject*)obj)->anim.velocityY = lbl_803E5A78;
    }

    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc,
                           lbl_803E5A7C, 0, (int)&hit_buf[0], obj,
                           8, -1, 0xff, 0xa) != 0)
    {
        Vec3_ReflectAgainstNormal((int)&hit_buf[7], obj + 0x24, (int)outV);
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
            int notifyArgB = (((SpscarabPlacement*)placement)->kind == 0) ? 1 : 0;
            int vendorObj = ((SpscarabState*)state)->vendorObj;
            int notifyArgA = (((SpscarabPlacement*)placement)->kind == 0) ? 0 : 1;
            (*(void (**)(int, int, int))(*(int*)(*(int*)(vendorObj + 0x68)) + 0x50))(
                vendorObj, notifyArgA, notifyArgB);
        }
    }

    if ((((GameObject*)obj)->objectFlags & 0x800) != 0)
    {
        if (((SpscarabState*)state)->burstCount != 0)
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E5A84, (u8)((SpscarabState*)state)->burstCount, 1, 0x14,
                                        lbl_803E5A88, 0, 0);
        }
    }
}

void spscarab_init(int obj, int def)
{
    extern int Obj_GetActiveModel(int obj);
    extern int randomGetRange(int lo, int hi);
    ObjAnimComponent* objAnim;
    int p_b8;
    int model;
    struct
    {
        u16 a;
        u8 b;
    } paletteBytes;

    objAnim = (ObjAnimComponent*)obj;
    p_b8 = *(int*)&((GameObject*)obj)->extra;
    paletteBytes.a = lbl_803E5A70;
    paletteBytes.b = lbl_803E5A72;

    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(s8) * (u8*)(def + 0x18) << 8);

    ((GameObject*)obj)->anim.velocityX =
        -mathSinf(lbl_803E5A8C * (f32)(s32)((GameObject*)obj)->anim.rotX /
            lbl_803E5A90);
    ((GameObject*)obj)->anim.velocityZ =
        -mathCosf(lbl_803E5A8C * (f32)(s32)((GameObject*)obj)->anim.rotX /
            lbl_803E5A90);

    objAnim->bankIndex = (s8)(1 - *(u8*)(def + 0x19));

    ((SpscarabState*)p_b8)->groundY = (f32)(s32) * (s16*)(def + 0x1a);
    ((SpscarabState*)p_b8)->speedScale = lbl_803E5A94 + randomGetRange(0, 0x64) / lbl_803E5A80;
    ((SpscarabState*)p_b8)->vendorObj = *(int*)(def + 0x14);
    *(int*)(def + 0x14) = -1;

    Sfx_AddLoopedObjectSound(obj, 0x406);
    model = Obj_GetActiveModel(obj);

    switch ((s8) * (u8*)(def + 0x19))
    {
    case 0:
        *(u8*)(*(int*)(model + 0x34) + 8) = *((u8*)&paletteBytes + randomGetRange(0, 2));
        ((SpscarabState*)p_b8)->sfxId = 0x41;
        ((SpscarabState*)p_b8)->mode = 4;
        ((SpscarabState*)p_b8)->burstCount = 2;
        break;
    case 1:
        ((SpscarabState*)p_b8)->sfxId = 0x42;
        ((SpscarabState*)p_b8)->mode = 1;
        ((SpscarabState*)p_b8)->burstCount = 0;
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
