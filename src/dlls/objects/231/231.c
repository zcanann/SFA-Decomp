/*
 * Flammable vine object family (DLL slot 231 / 0xE7).
 *
 * Hosts the flammablevine, CCeyeVines, and BurnableVin variants. A fire hit
 * sets the placement's burned game bit and starts a 240-frame burn cycle.
 * The burn animation, fade, particles, and looped sound advance until the
 * object is hidden and removed from the update list.
 *
 * A gated vine offers Tricky's side command only while its gate bit and the
 * Tricky Flame ability bit are set. A vine whose burned bit is already set
 * initializes in its consumed state.
 */
#include "dlls/objects/231.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/objtype.h"

#define FLAMMABLEVINE_SEQID_CC_EYE_VINES 0x102

#define FLAMMABLEVINE_OBJECT_GROUP      0x31
#define FLAMMABLEVINE_HIT_VOLUME_SLOT   9
#define FLAMMABLEVINE_IGNITION_HIT_TYPE 0x1A
#define FLAMMABLEVINE_SETUP_HIT_VOLUME  0
#define FLAMMABLEVINE_SETUP_POS_DIRTY   1

#define FLAMMABLEVINE_CC_EYE_PRIORITY_IDLE   0
#define FLAMMABLEVINE_CC_EYE_PRIORITY_ACTIVE 0x10

#define FLAMMABLEVINE_FLAG_BURNING  0x1
#define FLAMMABLEVINE_FLAG_CONSUMED 0x2
#define FLAMMABLEVINE_FLAG_INACTIVE (FLAMMABLEVINE_FLAG_BURNING | FLAMMABLEVINE_FLAG_CONSUMED)

#define FLAMMABLEVINE_BURN_DURATION        240.0f
#define FLAMMABLEVINE_BURN_ANIMATION_START 180.0f
#define FLAMMABLEVINE_BURN_FADE_START      150.0f
#define FLAMMABLEVINE_BURN_FULL_INTENSITY  120.0f
#define FLAMMABLEVINE_BURN_ANIMATION_RANGE 60.0f
#define FLAMMABLEVINE_BURN_FADE_RANGE      30.0f

#define FLAMMABLEVINE_DEFAULT_SCALE       5.0f
#define FLAMMABLEVINE_SCALE_DIVISOR       32767.0f
#define FLAMMABLEVINE_MIN_SCALE           0.05f
#define FLAMMABLEVINE_HITBOX_RADIUS_SCALE 14.0f
#define FLAMMABLEVINE_HITBOX_TOP_SCALE    25.0f
#define FLAMMABLEVINE_INITIAL_INTENSITY   0.001f
#define FLAMMABLEVINE_PARTICLE_SCALE      0.65f
#define FLAMMABLEVINE_PULSE_INTERVAL      1.0f
#define FLAMMABLEVINE_PULSE_STYLE_IDLE    0
#define FLAMMABLEVINE_PULSE_STYLE_ACTIVE  3

int FlammableVine_getExtraSize(void) {
    return sizeof(FlammableVineState);
}

int FlammableVine_getObjectTypeId(void) {
    return 0;
}

void FlammableVine_free(GameObject* obj) {
    objFreeObjectType(obj, FLAMMABLEVINE_OBJECT_GROUP);
}

void FlammableVine_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
    }
}

void FlammableVine_hitDetect(GameObject* obj) {
    FlammableVineState* state;
    FlammableVinePlacement* placement;
    u32 hitVolume;

    state = obj->extra;
    placement = (FlammableVinePlacement*)obj->anim.placementData;
    if ((state->flags & FLAMMABLEVINE_FLAG_INACTIVE) == 0) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitVolume) == FLAMMABLEVINE_IGNITION_HIT_TYPE) {
            if (placement->burnedBit != -1) {
                mainSetBits(placement->burnedBit, 1);
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
            }
            state->burnTimer = FLAMMABLEVINE_BURN_DURATION;
            state->flags |= FLAMMABLEVINE_FLAG_BURNING;
        }
    }
}

void FlammableVine_update(GameObject* obj) {
    FlammableVineState* state;
    FlammableVinePlacement* placement;
    GameObject* tricky;
    u8 canUse;
    f32 burnTimer;
    f32 zero;
    int pulseStyle;
    u32 fadeAlpha;

    state = obj->extra;
    placement = (FlammableVinePlacement*)obj->anim.placementData;
    tricky = getTrickyObject();

    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (placement->gateBit == -1 ||
        (mainGetBit(placement->gateBit) != 0 && tricky != NULL && mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0)) {
        canUse = 1;
    } else {
        canUse = 0;
    }

    if ((state->flags & FLAMMABLEVINE_FLAG_INACTIVE) == 0) {
        if (state->setupParam == FLAMMABLEVINE_SETUP_HIT_VOLUME) {
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FLAMMABLEVINE_HIT_VOLUME_SLOT, 1, 0);
        }
        ObjHits_EnableObject(obj);

        if (obj->anim.romDefNo == FLAMMABLEVINE_SEQID_CC_EYE_VINES) {
            if (cMenuGetSelectedItem() == -1) {
                obj->anim.modelInstance->hitVolumes[0].priority = FLAMMABLEVINE_CC_EYE_PRIORITY_IDLE;
            } else {
                obj->anim.modelInstance->hitVolumes[0].priority = FLAMMABLEVINE_CC_EYE_PRIORITY_ACTIVE;
            }
        }

        if (tricky != NULL && canUse != 0) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
                TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, 1, 4);
            }
        }
    }

    burnTimer = state->burnTimer;
    zero = 0.0f;
    if (burnTimer > zero) {
        state->burnTimer = burnTimer - timeDelta;
        if (state->burnTimer <= zero) {
            obj->anim.alpha = 0;
            state->burnTimer = zero;
            state->flags &= ~FLAMMABLEVINE_FLAG_BURNING;
            state->flags |= FLAMMABLEVINE_FLAG_CONSUMED;
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
        }
    }

    if ((state->flags & FLAMMABLEVINE_FLAG_BURNING) != 0) {
        if (state->burnTimer < FLAMMABLEVINE_BURN_FULL_INTENSITY) {
            state->burnIntensity = 1.0f;
        } else {
            state->burnIntensity =
                1.0f - ((state->burnTimer - FLAMMABLEVINE_BURN_FULL_INTENSITY) / FLAMMABLEVINE_BURN_FULL_INTENSITY);
        }

        if (state->burnTimer < FLAMMABLEVINE_BURN_ANIMATION_START &&
            state->burnTimer > FLAMMABLEVINE_BURN_FULL_INTENSITY) {
            ObjAnim_SetMoveProgress(
                (ObjAnimComponent*)obj,
                1.0f - ((state->burnTimer - FLAMMABLEVINE_BURN_FULL_INTENSITY) / FLAMMABLEVINE_BURN_ANIMATION_RANGE));
        }

        if (state->burnTimer < FLAMMABLEVINE_BURN_FADE_START) {
            if (state->burnTimer < FLAMMABLEVINE_BURN_FULL_INTENSITY) {
                obj->anim.alpha = 0;
            } else {
                fadeAlpha = (u8)(255.0f * ((state->burnTimer - FLAMMABLEVINE_BURN_FULL_INTENSITY) /
                                           FLAMMABLEVINE_BURN_FADE_RANGE));
                obj->anim.alpha = fadeAlpha;
            }
        }

        state->pulseTimer -= timeDelta;
        if (state->pulseTimer <= 0.0f) {
            pulseStyle = FLAMMABLEVINE_PULSE_STYLE_ACTIVE;
            state->pulseTimer += FLAMMABLEVINE_PULSE_INTERVAL;
        } else {
            pulseStyle = FLAMMABLEVINE_PULSE_STYLE_IDLE;
        }
        objfx_spawnPulseBurst(obj, FLAMMABLEVINE_PARTICLE_SCALE * (state->burnIntensity * obj->anim.rootMotionScale), 3, 0,
                    pulseStyle, NULL);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
    }
}

void FlammableVine_init(GameObject* obj, FlammableVinePlacement* placement) {
    FlammableVineState* state;
    f32 scale;

    state = obj->extra;
    objAddObjectType(obj, FLAMMABLEVINE_OBJECT_GROUP);
    obj->anim.rotX = (s16)(placement->rotXByte << 8);

    obj->anim.rootMotionScale =
        FLAMMABLEVINE_DEFAULT_SCALE * ((f32)placement->scaleParam / FLAMMABLEVINE_SCALE_DIVISOR);
    if (obj->anim.rootMotionScale <= FLAMMABLEVINE_MIN_SCALE) {
        obj->anim.rootMotionScale = FLAMMABLEVINE_MIN_SCALE;
    }

    scale = obj->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, (s16)(FLAMMABLEVINE_HITBOX_RADIUS_SCALE * scale), 0,
                               (s16)(FLAMMABLEVINE_HITBOX_TOP_SCALE * scale));
    state->burnIntensity = FLAMMABLEVINE_INITIAL_INTENSITY;
    ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, 0.0f);

    if (placement->burnedBit != -1 && mainGetBit(placement->burnedBit) != 0) {
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
        obj->anim.alpha = 0;
        state->flags |= FLAMMABLEVINE_FLAG_CONSUMED;
    }

    state->setupParam = placement->setupParam;
    if (state->setupParam == FLAMMABLEVINE_SETUP_POS_DIRTY) {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
}

void FlammableVine_release(void) {
}

void FlammableVine_initialise(void) {
}

ObjectDescriptor gFlammableVineObjDescriptor = {
    0,                                                       /* reserved0 */
    0,                                                       /* reserved1 */
    0,                                                       /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,                        /* slotCountAndFlags */
    (ObjectDescriptorCallback)FlammableVine_initialise,      /* initialise */
    (ObjectDescriptorCallback)FlammableVine_release,         /* release */
    0,                                                       /* slot02 */
    (ObjectDescriptorCallback)FlammableVine_init,            /* init */
    (ObjectDescriptorCallback)FlammableVine_update,          /* update */
    (ObjectDescriptorCallback)FlammableVine_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)FlammableVine_render,          /* render */
    (ObjectDescriptorCallback)FlammableVine_free,            /* free */
    (ObjectDescriptorCallback)FlammableVine_getObjectTypeId, /* getObjectTypeId */
    FlammableVine_getExtraSize,                              /* getExtraSize */
};
