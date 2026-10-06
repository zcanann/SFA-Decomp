/*
 * DIM2Icicle (DLL 0x1DD) - hanging icicle object for DarkIce Mines 2.
 * A hit makes the icicle wobble, then fall toward a water surface. After
 * impact, it fades away and resets to its placement height.
 */
#include "dlls/objects/477_DIM2Icicle.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/waterfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/track_dolphin_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"
#include "main/vecmath.h"

#define DIM2ICICLE_RELEASE_HIT_TYPE   0xE
#define DIM2ICICLE_WATER_SURFACE_TYPE 0xE
#define DIM2ICICLE_DROP_Y_SENTINEL    -100000.0f

typedef enum Dim2IcicleMode {
    DIM2ICICLE_MODE_WAIT_FOR_HIT = 0,
    DIM2ICICLE_MODE_DROPPING = 1,
    DIM2ICICLE_MODE_IMPACTED = 2,
    DIM2ICICLE_MODE_WOBBLING = 3,
} Dim2IcicleMode;

int dim2icicle_getExtraSize(void) {
    return sizeof(Dim2IcicleState);
}

int dim2icicle_getObjectTypeId(void) {
    return 0;
}

void dim2icicle_free(void) {
}

void dim2icicle_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim2icicle_hitDetect(void) {
}

void dim2icicle_update(GameObject* obj) {
    ObjHitsPriorityState* hitState;
    Dim2IcicleState* state;
    const Dim2IciclePlacementView* placement;

    placement = (const Dim2IciclePlacementView*)obj->anim.placementData;
    state = obj->extra;
    switch (state->mode) {
    case DIM2ICICLE_MODE_WAIT_FOR_HIT:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != DIM2ICICLE_RELEASE_HIT_TYPE) {
            break;
        }
        state->wobbleRotationY = randomGetRange(0x320, 0x4B0);
        state->mode = DIM2ICICLE_MODE_WOBBLING;
        hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        Sfx_PlayFromObject(obj, SFXTRIG_en_sbalhis6);
        break;
    case DIM2ICICLE_MODE_WOBBLING: {
        obj->anim.rotY = state->wobbleRotationY;
        state->wobbleRotationY *= 0.333f;
        if (obj->anim.rotY >= 10) {
            break;
        }
        obj->anim.rotY = 0;
        state->mode = DIM2ICICLE_MODE_DROPPING;
        state->timer = 0x3C;
        break;
    }
    case DIM2ICICLE_MODE_DROPPING:
        if (state->dropTargetFound == 0) {
            int hitCount;
            int hitIndex;
            TrackGroundHit** groundHits;

            hitCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                            &groundHits, 0, 0);
            state->dropTargetY = DIM2ICICLE_DROP_Y_SENTINEL;
            for (hitIndex = 0; hitIndex < hitCount; hitIndex++) {
                TrackGroundHit* groundHit = groundHits[hitIndex];

                if ((s8)groundHit->surfaceType == DIM2ICICLE_WATER_SURFACE_TYPE) {
                    state->dropTargetY = groundHit->height;
                    hitIndex = hitCount;
                }
            }
            if (DIM2ICICLE_DROP_Y_SENTINEL != state->dropTargetY) {
                state->dropTargetFound = 1;
            }
        }
        if (state->timer > 0) {
            state->timer -= framesThisStep;
            if (state->timer <= 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_swdwood16);
            }
        }
        obj->anim.velocityY = -(0.1f * timeDelta - obj->anim.velocityY);
        if (obj->anim.velocityY < -10.0f) {
            obj->anim.velocityY = -10.0f;
        }
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        if (obj->anim.localPosY < state->dropTargetY) {
            mainSetBits(placement->impactGameBit, 1);
            state->mode = DIM2ICICLE_MODE_IMPACTED;
            (*gWaterfxInterface)
                ->spawnSplashBurst(obj, obj->anim.localPosX, state->dropTargetY, obj->anim.localPosZ, 10.0f);
            (*gWaterfxInterface)
                ->spawnCircularRipple(obj->anim.localPosX, state->dropTargetY, obj->anim.localPosZ, 0, 0.0f, 2);
            Sfx_PlayFromObject(obj, SFXTRIG_mv_curtainopen16);
            state->timer = 0x96;
        }
        break;
    case DIM2ICICLE_MODE_IMPACTED:
    default:
        if (state->timer > 0) {
            state->timer -= framesThisStep;
            if (state->timer <= 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_155);
            }
        }
        {
            int alpha = obj->anim.alpha - framesThisStep * 8;

            if (alpha < 0) {
                alpha = 0;
                obj->anim.localPosY = placement->base.posY;
                obj->anim.velocityY = 0.0f;
            }
            obj->anim.alpha = alpha;
        }
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        break;
    }
}

void dim2icicle_init(GameObject* obj, const Dim2IciclePlacementView* placement) {
    Dim2IcicleState* state = obj->extra;

    if (mainGetBit(placement->impactGameBit) != 0) {
        state->mode = DIM2ICICLE_MODE_IMPACTED;
        obj->anim.alpha = 0;
    } else {
        state->mode = DIM2ICICLE_MODE_WAIT_FOR_HIT;
        obj->anim.alpha = 0xFF;
    }
    obj->anim.rotX = (s16)((s32)placement->rotationXByte << 8);
    obj->anim.velocityY = 0.0f;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dim2icicle_release(void) {
}

void dim2icicle_initialise(void) {
}

ObjectDescriptor gDIM2IcicleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dim2icicle_initialise,
    (ObjectDescriptorCallback)dim2icicle_release,
    0,
    (ObjectDescriptorCallback)dim2icicle_init,
    (ObjectDescriptorCallback)dim2icicle_update,
    (ObjectDescriptorCallback)dim2icicle_hitDetect,
    (ObjectDescriptorCallback)dim2icicle_render,
    (ObjectDescriptorCallback)dim2icicle_free,
    (ObjectDescriptorCallback)dim2icicle_getObjectTypeId,
    dim2icicle_getExtraSize,
};
