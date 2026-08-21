/*
 * DLL 0xF7 - unnamed two-hit breakable object.
 *
 * Hits briefly bounce the model. Destruction records the placement game bit
 * and either spawns an EnergyEgg or moves a nearby collectible into place.
 */
#include "dlls/objects/247.h"
#include "dlls/objects/237.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/dll_005B_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/frame_timing.h"
#include "main/mapEventTypes.h"
#include "main/objprint_api.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/gamebits_api.h"
#include "main/objhits.h"

#define DLLF7_OBJECT_TYPE_ID 2

#define DLLF7_OBJECT_GROUP 0x3E

#define DLLF7_RESOURCE_STAFF_COLLISION 0x5A
#define DLLF7_RESOURCE_MODGFX          0x5B

#define DLLF7_HIT_COUNT                 2
#define DLLF7_MODEL_FLAGS               0x810
#define DLLF7_RENDER_RED                0xC8
#define DLLF7_BREAK_TIME                1200.0f
#define DLLF7_BOUNCE_START_OFFSET       1.0f
#define DLLF7_BOUNCE_START_VELOCITY     12.0f
#define DLLF7_BOUNCE_MAX_OFFSET         120.0f
#define DLLF7_COLLECTIBLE_Y_OFFSET      10.0f
#define DLLF7_COLLECTIBLE_SEARCH_RADIUS 50.0f
#define DLLF7_HIT_PARTICLE_FLAGS        0x401

struct DllF7Placement {
    ObjPlacement base;   /* 0x00 */
    s8 rotXByte;         /* 0x18: X rotation in 1/256 turns */
    u8 alternateMode;    /* 0x19 */
    u8 pad1A[4];         /* 0x1A */
    s16 completeGameBit; /* 0x1E: set when the object breaks; -1 = none */
};

typedef struct DllF7HitEffect {
    StaffCollisionColorArgs color;
    PartFxSpawnParams spawn;
} DllF7HitEffect;

const StaffCollisionColorArgs sStaffHitEffectColor = {8, 0xFF, 0xFF, 0x78};

typedef struct DllF7State {
    f32 bounceOffset;   /* 0x00 */
    f32 bounceVelocity; /* 0x04 */
    u8 unk08;           /* 0x08 */
    s8 broken;          /* 0x09 */
    s8 hitsRemaining;   /* 0x0A */
    s8 alternateMode;   /* 0x0B */
} DllF7State;

STATIC_ASSERT(offsetof(DllF7Placement, base) == 0x0);
STATIC_ASSERT(offsetof(DllF7Placement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DllF7Placement, alternateMode) == 0x19);
STATIC_ASSERT(offsetof(DllF7Placement, pad1A) == 0x1A);
STATIC_ASSERT(offsetof(DllF7Placement, completeGameBit) == 0x1E);

STATIC_ASSERT(offsetof(DllF7HitEffect, color) == 0x0);
STATIC_ASSERT(offsetof(DllF7HitEffect, spawn) == 0x10);
STATIC_ASSERT(sizeof(DllF7HitEffect) == 0x28);

STATIC_ASSERT(offsetof(DllF7State, bounceOffset) == 0x0);
STATIC_ASSERT(offsetof(DllF7State, bounceVelocity) == 0x4);
STATIC_ASSERT(offsetof(DllF7State, unk08) == 0x8);
STATIC_ASSERT(offsetof(DllF7State, broken) == 0x9);
STATIC_ASSERT(offsetof(DllF7State, hitsRemaining) == 0xA);
STATIC_ASSERT(offsetof(DllF7State, alternateMode) == 0xB);
STATIC_ASSERT(sizeof(DllF7State) == 0xC);

StaffCollisionInterface** gDllF7Resource5A;
Dll5BInterface** gDllF7Resource5B;

int dll_F7_getExtraSize(void) {
    return sizeof(DllF7State);
}

int dll_F7_getObjectTypeId(void) {
    return DLLF7_OBJECT_TYPE_ID;
}

void dll_F7_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource((void*)obj);
    Resource_Release(gDllF7Resource5B);
    Resource_Release(gDllF7Resource5A);
    gDllF7Resource5B = NULL;
    gDllF7Resource5A = NULL;
    objFreeObjectType(obj, DLLF7_OBJECT_GROUP);
}

void dll_F7_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    DllF7State* state = obj->extra;

    if (state->broken == 0 && visible != 0) {
        f32 bounceOffset = state->bounceOffset;
        if (bounceOffset) {
            objSetGlowColor(DLLF7_RENDER_RED, 0, 0, bounceOffset);
        }
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void dll_F7_hitDetect(void) {
}

void dll_F7_update(GameObject* obj) {
    DllF7State* state = obj->extra;
    DllF7HitEffect hitEffect;
    f32 radius;
    u32 hitVolume;
    u8 canSetupObject;

    hitEffect.color = sStaffHitEffectColor;
    if (state->broken != 0) {
        DllF7Placement* placement = (DllF7Placement*)obj->anim.placementData;
        if (state->alternateMode == 0 && (*gMapEventInterface)->shouldNotSaveTime(placement->base.ident) != 0) {
            state->broken = 0;
            state->unk08 = 1;
            state->hitsRemaining = DLLF7_HIT_COUNT;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        } else {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        return;
    }
    if (ObjHits_GetPriorityHitWithPosition(obj, 0, 0, &hitVolume, &hitEffect.spawn.posX, &hitEffect.spawn.posY,
                                           &hitEffect.spawn.posZ) != 0) {
        if ((state->hitsRemaining -= hitVolume) > 0) {
            Sfx_PlayAtPositionFromObject(obj, hitEffect.spawn.posX, hitEffect.spawn.posY, hitEffect.spawn.posZ,
                                         SFXTRIG_crtsmsh6);
            Obj_SetActiveModelIndex(obj, DLLF7_HIT_COUNT - state->hitsRemaining);
            state->bounceOffset = DLLF7_BOUNCE_START_OFFSET;
            state->bounceVelocity = DLLF7_BOUNCE_START_VELOCITY;
            hitEffect.spawn.posX += playerMapOffsetX;
            hitEffect.spawn.posZ += playerMapOffsetZ;
            hitEffect.spawn.scale = 1.0f;
            hitEffect.spawn.rotZ = 0;
            hitEffect.spawn.rotY = 0;
            hitEffect.spawn.rotX = 0;
            (*gDllF7Resource5A)
                ->spawn(NULL, 1, (PartFxSpawnParams*)((int)&hitEffect + 16), DLLF7_HIT_PARTICLE_FLAGS, -1,
                        &hitEffect.color);
        }
    }
    if (state->hitsRemaining <= 0) {
        DllF7Placement* placement = (DllF7Placement*)obj->anim.placementData;
        if (state->alternateMode == 0) {
            (*gMapEventInterface)->addTime(placement->base.ident, DLLF7_BREAK_TIME);
        }
        state->broken = 1;
        state->unk08 = 0;
        Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        if ((int)placement->completeGameBit != -1) {
            mainSetBits((int)placement->completeGameBit, 1);
        }
        if (state->alternateMode == 0 && (canSetupObject = Obj_CanSetupObject()) > 0) {
            CollectibleSetup* setup =
                (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), COLLECTIBLE_ITEM_ENERGY_EGG);
            setup->hideGameBit = -1;
            setup->base.posX = obj->anim.localPosX;
            setup->base.posY = DLLF7_COLLECTIBLE_Y_OFFSET + obj->anim.localPosY;
            setup->base.posZ = obj->anim.localPosZ;
            setup->unk1A = 3;
            setup->counterGameBit = -1;
            setup->visibilityGameBit = -1;
            objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        } else {
            GameObject* collectible;

            radius = DLLF7_COLLECTIBLE_SEARCH_RADIUS;
            collectible = objGetNearestTypeTo(COLLECTIBLE_OBJECT_GROUP, obj, &radius);
            if (collectible != NULL) {
                collectible->anim.localPosX = collectible->anim.worldPosX = obj->anim.localPosX;
                collectible->anim.localPosY = collectible->anim.worldPosY =
                    DLLF7_COLLECTIBLE_Y_OFFSET + obj->anim.localPosY;
                collectible->anim.localPosZ = collectible->anim.worldPosZ = obj->anim.localPosZ;
                collectible->anim.rotX = obj->anim.rotX;
            }
        }
        (*gDllF7Resource5B)->spawn(obj, 1, NULL, 2, -1, NULL);
    }
    if (state->bounceOffset > 0.0f) {
        state->bounceOffset = timeDelta * state->bounceVelocity + state->bounceOffset;
        if (state->bounceOffset < 0.0f) {
            state->bounceOffset = 0.0f;
        } else if (state->bounceOffset > DLLF7_BOUNCE_MAX_OFFSET) {
            state->bounceOffset = DLLF7_BOUNCE_MAX_OFFSET - (state->bounceOffset - DLLF7_BOUNCE_MAX_OFFSET);
            state->bounceVelocity = -state->bounceVelocity;
        }
    }
}

void dll_F7_init(GameObject* obj, DllF7Placement* placement) {
    DllF7State* state = obj->extra;

    objAddObjectType(obj, DLLF7_OBJECT_GROUP);
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    gDllF7Resource5B = Resource_Acquire(DLLF7_RESOURCE_MODGFX, 1);
    gDllF7Resource5A = Resource_Acquire(DLLF7_RESOURCE_STAFF_COLLISION, 1);
    {
        ObjModelState* modelState = obj->anim.modelState;
        if (modelState != NULL) {
            modelState->flags |= DLLF7_MODEL_FLAGS;
        }
    }
    state->hitsRemaining = DLLF7_HIT_COUNT;
    *(u8*)&state->alternateMode = placement->alternateMode;
    if (state->alternateMode == 0) {
        int mapEventState = (*gMapEventInterface)->shouldNotSaveTime(placement->base.ident);
        if (mapEventState == 0) {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            *(u8*)&state->broken = 1;
            state->unk08 = 0;
        }
    }
}

void dll_F7_release(void) {
}

void dll_F7_initialise(void) {
}

ObjectDescriptor dll_F7 = {
    0,                                                /* reserved0 */
    0,                                                /* reserved1 */
    0,                                                /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                 /* slotCountAndFlags */
    (ObjectDescriptorCallback)dll_F7_initialise,      /* initialise */
    (ObjectDescriptorCallback)dll_F7_release,         /* release */
    0,                                                /* slot02 */
    (ObjectDescriptorCallback)dll_F7_init,            /* init */
    (ObjectDescriptorCallback)dll_F7_update,          /* update */
    (ObjectDescriptorCallback)dll_F7_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)dll_F7_render,          /* render */
    (ObjectDescriptorCallback)dll_F7_free,            /* free */
    (ObjectDescriptorCallback)dll_F7_getObjectTypeId, /* getObjectTypeId */
    dll_F7_getExtraSize,                              /* getExtraSize */
};
