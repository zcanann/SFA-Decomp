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
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"

STATIC_ASSERT(sizeof(ShopItemState) == 0xEC);
STATIC_ASSERT(sizeof(ShopkeeperState) == 0x9D8);
STATIC_ASSERT(offsetof(ShopkeeperState, msgStack) == 0x9B0);

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

#define SPSCARAB_OBJFLAG_RENDERED           0x800
#define SPSCARAB_OBJFLAG_HIDDEN             0x4000
#define SPSCARAB_OBJFLAG_HITDETECT_DISABLED 0x2000
#define SPSCARAB_OBJFLAG_UPDATE_DISABLED    0x8000

extern u16 gSpScarabPaletteBytesA;
extern u8 gSpScarabPaletteByteB;
extern f32 gSpScarabGravity;             /* gravity */
extern f32 gSpScarabBounceVelocityY;     /* ground-bounce velocityY */
extern f32 gSpScarabCollisionRadius;     /* bbox collision radius */
extern f32 gSpScarabPickupRadius;        /* pickup radius */
extern f32 gSpScarabPickupParticleScale; /* pickup particle scale */
extern f32 gSpScarabDustBurstScale;      /* dust-burst scale */
extern f32 gSpScarabPi;
extern f32 gSpScarabAngleToRadiansDivisor;
extern f32 gSpScarabBaseSpeedScale; /* base horizontal speed scale */

extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void itemPickupDoParticleFx(int obj, f32 a, int b, int c);

int SPScarab_getExtraSize(void)
{
    return 0x14;
}
int SPScarab_getObjectTypeId(void)
{
    return 0x0;
}

void SPScarab_free(int obj)
{
    Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_scarab_runloop);
}

void SPScarab_render(void)
{
}

void SPScarab_hitDetect(void)
{
}

void SPScarab_update(int obj)
{
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
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - gSpScarabGravity * timeDelta;
    }

    objMove((GameObject*)obj, timeDelta * (((GameObject*)obj)->anim.velocityX * ((SpscarabState*)state)->speedScale),
            ((GameObject*)obj)->anim.velocityY * timeDelta,
            timeDelta * (((GameObject*)obj)->anim.velocityZ * ((SpscarabState*)state)->speedScale));

    distance = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                     ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);

    ObjAnim_SampleRootCurvePhase(distance, (ObjAnimComponent*)obj, &phase);
    ObjAnim_AdvanceCurrentMove((int)obj, phase, timeDelta, 0);

    if (((GameObject*)obj)->anim.localPosY < ((SpscarabState*)state)->groundY)
    {
        ((GameObject*)obj)->anim.localPosY = ((SpscarabState*)state)->groundY;
        ((GameObject*)obj)->anim.velocityY = gSpScarabBounceVelocityY;
    }

    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc, gSpScarabCollisionRadius, 0, (int)&hit_buf[0], obj, 8, -1, 0xff,
                           0xa) != 0)
    {
        Vec3_ReflectAgainstNormal((f32*)&hit_buf[7], (f32*)(obj + 0x24), outV);
        ((GameObject*)obj)->anim.velocityX = outV[0];
        ((GameObject*)obj)->anim.velocityZ = outV[2];
        angle = (s16)getAngle(-((GameObject*)obj)->anim.velocityX, -((GameObject*)obj)->anim.velocityZ);
        ((GameObject*)obj)->anim.rotX = angle;
    }

    if (getXZDistance(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX,
                      &((GameObject*)obj)->anim.worldPosX) <
        gSpScarabPickupRadius)
    {
        Sfx_PlayFromObject(obj, (u16)((SpscarabState*)state)->sfxId);
        itemPickupDoParticleFx(obj, gSpScarabPickupParticleScale, ((SpscarabState*)state)->mode, 0x28);
        ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | SPSCARAB_OBJFLAG_UPDATE_DISABLED;
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;

        {
            int notifyArgB = (((SpscarabPlacement*)placement)->kind == 0) ? 1 : 0;
            int vendorObj = ((SpscarabState*)state)->vendorObj;
            int notifyArgA = (((SpscarabPlacement*)placement)->kind == 0) ? 0 : 1;
            (*(void (**)(int, int, int))(*(int*)(*(int*)(vendorObj + 0x68)) + 0x50))(vendorObj, notifyArgA, notifyArgB);
        }
    }

    if ((((GameObject*)obj)->objectFlags & SPSCARAB_OBJFLAG_RENDERED) != 0)
    {
        if (((SpscarabState*)state)->burstCount != 0)
        {
            objfx_spawnDirectionalBurstLegacy(obj, 5, gSpScarabPickupParticleScale, (u8)((SpscarabState*)state)->burstCount,
                                        1, 0x14, gSpScarabDustBurstScale, 0, 0);
        }
    }
}

void SPScarab_init(GameObject* obj, int def)
{
    ObjAnimComponent* objAnim;
    int state;
    int model;
    struct
    {
        u16 pairAB;
        u8 byteC;
    } paletteBytes;

    objAnim = (ObjAnimComponent*)obj;
    state = *(int*)&(obj)->extra;
    paletteBytes.pairAB = gSpScarabPaletteBytesA;
    paletteBytes.byteC = gSpScarabPaletteByteB;

    (obj)->objectFlags = (obj)->objectFlags | (SPSCARAB_OBJFLAG_HIDDEN | SPSCARAB_OBJFLAG_HITDETECT_DISABLED);
    (obj)->anim.rotX = (s16)((s32)(s8) * (u8*)(def + 0x18) << 8);

    (obj)->anim.velocityX = -mathSinf(gSpScarabPi * (f32)(s32)(obj)->anim.rotX / gSpScarabAngleToRadiansDivisor);
    (obj)->anim.velocityZ = -mathCosf(gSpScarabPi * (f32)(s32)(obj)->anim.rotX / gSpScarabAngleToRadiansDivisor);

    objAnim->bankIndex = (s8)(1 - *(u8*)(def + 0x19));

    ((SpscarabState*)state)->groundY = (f32)(s32) * (s16*)(def + 0x1a);
    ((SpscarabState*)state)->speedScale = gSpScarabBaseSpeedScale + randomGetRange(0, 0x64) / gSpScarabPickupRadius;
    ((SpscarabState*)state)->vendorObj = *(int*)(def + 0x14);
    *(int*)(def + 0x14) = -1;

    Sfx_AddLoopedObjectSound((int)obj, SFXTRIG_scarab_runloop);
    model = (int)Obj_GetActiveModel(obj);

    switch ((s8) * (u8*)(def + 0x19))
    {
    case 0:
        *(u8*)(*(int*)(model + 0x34) + 8) = *((u8*)&paletteBytes + randomGetRange(0, 2));
        ((SpscarabState*)state)->sfxId = 0x41;
        ((SpscarabState*)state)->mode = 4;
        ((SpscarabState*)state)->burstCount = 2;
        break;
    case 1:
        ((SpscarabState*)state)->sfxId = 0x42;
        ((SpscarabState*)state)->mode = 1;
        ((SpscarabState*)state)->burstCount = 0;
        break;
    }
}

void SPScarab_release(void)
{
}

void SPScarab_initialise(void)
{
}

ObjectDescriptor gSPScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SPScarab_initialise,
    (ObjectDescriptorCallback)SPScarab_release,
    0,
    (ObjectDescriptorCallback)SPScarab_init,
    (ObjectDescriptorCallback)SPScarab_update,
    (ObjectDescriptorCallback)SPScarab_hitDetect,
    (ObjectDescriptorCallback)SPScarab_render,
    (ObjectDescriptorCallback)SPScarab_free,
    (ObjectDescriptorCallback)SPScarab_getObjectTypeId,
    SPScarab_getExtraSize,
};
