/*
 * SPScarab (DLL 647) - the scarab coin / pickup that the shopkeeper
 * scatters when paid (see SPShopKeepe's ShopKeeper_spawnScarabs, which spawns object
 * type 1151 = this object).
 *
 * Each scarab is launched along its facing angle, falls under gravity and
 * bounces off geometry (trackGetLineIntersect + Vec3_ReflectAgainstNormal),
 * resting on a placement-supplied ground height. When the player comes
 * within pickupRadius it plays its pickup sfx, emits collection particles,
 * marks itself for despawn and notifies the owning shop object through its
 * interface vtable. Two kinds (placement->kind 0/1) differ only in sfx,
 * particle mode and the trailing dust-burst count.
 */
#include "main/dll/SP/dll_0285_spshop.h"
#include "main/dll/SP/dll_0287_spscarab.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "sys/objects.h"
#include "main/track_bbox_api.h"
#include "main/objfx.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"

typedef struct
{
    u16 pairAB;
    u8 byteC;
} SpscarabPalette;

const u16 gSpScarabPaletteBytesA = 0x0213;
const u8 gSpScarabPaletteByteB = 0x16;

typedef struct SpscarabPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 vendorObj; /* 0x14: owning shop object; consumed (set -1) by init */
    s8 rotXByte;   /* 0x18: initial facing angle byte */
    s8 kind;       /* 0x19: scarab variant (0 / 1) */
    s16 groundY;   /* 0x1A: rest height */
    u8 pad1C[0x20 - 0x1C];
} SpscarabPlacement;

STATIC_ASSERT(offsetof(SpscarabPlacement, vendorObj) == 0x14);
STATIC_ASSERT(offsetof(SpscarabPlacement, kind) == 0x19);
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

int SPScarab_getExtraSize(void)
{
    return 0x14;
}
int SPScarab_getObjectTypeId(void)
{
    return 0x0;
}

void SPScarab_free(GameObject* obj)
{
    Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_scarab_runloop);
}

void SPScarab_render(void)
{
}

void SPScarab_hitDetect(void)
{
}

void SPScarab_update(GameObject* obj)
{
    SpscarabState* state;
    SpscarabPlacement* placement;
    s16 angle;
    f32 distance;
    f32 phase;
    f32 outV[3];
    TrackLineIntersectResult hit_buf;

    state = (SpscarabState*)obj->extra;
    placement = (SpscarabPlacement*)obj->anim.placementData;

    if (obj->anim.localPosY > state->groundY)
    {
        obj->anim.velocityY = obj->anim.velocityY - 0.1f * timeDelta;
    }

    objMove(obj, timeDelta * (obj->anim.velocityX * state->speedScale),
            obj->anim.velocityY * timeDelta,
            timeDelta * (obj->anim.velocityZ * state->speedScale));

    distance = sqrtf(obj->anim.velocityX * obj->anim.velocityX +
                     obj->anim.velocityZ * obj->anim.velocityZ);

    ObjAnim_SampleRootCurvePhase(&obj->anim, distance, &phase);
    ObjAnim_AdvanceCurrentMove(obj, phase, timeDelta, 0);

    if (obj->anim.localPosY < state->groundY)
    {
        obj->anim.localPosY = state->groundY;
        obj->anim.velocityY = 0.0f;
    }

    if (trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 3.0f, 0,
                           &hit_buf, obj, 8, -1, 0xff, 0xa) != 0)
    {
        Vec3_ReflectAgainstNormal(&hit_buf.normalX, &obj->anim.velocityX, outV);
        obj->anim.velocityX = outV[0];
        obj->anim.velocityZ = outV[2];
        angle = (s16)getAngle(-obj->anim.velocityX, -obj->anim.velocityZ);
        obj->anim.rotX = angle;
    }

    if (getXZDistanceSquared(&Obj_GetPlayerObject()->anim.worldPosX,
                      &obj->anim.worldPosX) <
        100.0f)
    {
        Sfx_PlayFromObject(obj, (u16)state->sfxId);
        itemPickupDoParticleFx(obj, 1.0f, state->mode, 0x28);
        obj->objectFlags = obj->objectFlags | OBJECT_OBJFLAG_UPDATE_DISABLED;
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;

        {
            int notifyArgB = (placement->kind == 0) ? 1 : 0;
            int vendorObj = state->vendorObj;
            int notifyArgA = (placement->kind == 0) ? 0 : 1;
            SHOP_INTERFACE(vendorObj)->func16((GameObject*)vendorObj, notifyArgA, notifyArgB);
        }
    }

    if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0)
    {
        if (state->burstCount != 0)
        {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, state->burstCount, 1, 0x14,
                                        2.5f, NULL, 0);
        }
    }
}

void SPScarab_init(GameObject* obj, SpscarabPlacement* def)
{
    ObjAnimComponent* objAnim;
    SpscarabState* state;
    ObjModel* model;
    SpscarabPalette paletteBytes;

    objAnim = &obj->anim;
    state = (SpscarabState*)obj->extra;
    {
        const u16* palettePair = &gSpScarabPaletteBytesA;
        const u8* paletteByte = &gSpScarabPaletteByteB;
        paletteBytes.pairAB = *palettePair;
        paletteBytes.byteC = *paletteByte;
    }

    obj->objectFlags = obj->objectFlags | (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->anim.rotX = (s16)((s32)def->rotXByte << 8);

    obj->anim.velocityX = -mathSinf(3.1415927f * (f32)(s32)obj->anim.rotX / 32768.0f);
    obj->anim.velocityZ = -mathCosf(3.1415927f * (f32)(s32)obj->anim.rotX / 32768.0f);

    objAnim->bankIndex = (s8)(1 - def->kind);

    state->groundY = (f32)(s32)def->groundY;
    state->speedScale = 0.4f + randomGetRange(0, 0x64) / 100.0f;
    state->vendorObj = def->vendorObj;
    def->vendorObj = -1;

    Sfx_AddLoopedObjectSound(obj, SFXTRIG_scarab_runloop);
    model = Obj_GetActiveModel(obj);

    switch (def->kind)
    {
    case 0:
        model->textureRefs->swapSelector = *((u8*)&paletteBytes + randomGetRange(0, 2));
        state->sfxId = 0x41;
        state->mode = 4;
        state->burstCount = 2;
        break;
    case 1:
        state->sfxId = 0x42;
        state->mode = 1;
        state->burstCount = 0;
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
