/*
 * SB_Propeller (DLL 0x01E9) - a spinning propeller blade on General Scales'
 * galleon in the ShipBattle prologue (SB = the retail "ShipBattle" map).
 * The player must shoot out the propellers (after the first deck-gun phase)
 * to keep bringing the galleon down. While the Galleon is intact the
 * propeller emits its loop sfx and spins; once the Galleon's camera/cutscene
 * state lets it take damage the propeller streams smoke, takes hits from the
 * Cloudrunner, and on death plays an explosion and hides itself. The
 * propeller queries the parent Galleon through its anim.dll vtable
 * (offsets 0x20/0x24/0x28) for camera/state info.
 */
#include "dlls/objects/489_SB_Propelle.h"

#include "dlls/objects/488_SB_Galleon.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/obj_path.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects.h"

/* anim.romDefNo tag identifying a live propeller (vs. a placeholder stand-in) */
#define SB_PROPELLER_SEQ_ID 0x69c
/* a second SB object's romDefNo the propeller ignores when scanning hits */
#define SB_OTHER_SEQ_ID 0x9a

/* propeller sound effects (SB-specific ids, no shared name) */
#define SB_PROPELLER_SFX_LOOP      0x2c6
#define SB_PROPELLER_SFX_HIT       0x2c7
#define SB_PROPELLER_SFX_DESTROYED 0x2c8

/* partfx emitted once the propeller is destroyed (health <= 0) */
#define SB_PROPELLER_PARTFX_SMOKE  0x9f  /* smokeTimer-gated smoke burst at the hub */
#define SB_PROPELLER_PARTFX_DEBRIS 0x7aa /* bankIndex==1 debris trail from path point 0 */

GameObject* gSbPropellerObject;

GameObject* sbGetPropeller(void) {
    return gSbPropellerObject;
}

int SB_Propeller_getExtraSize(void) {
    return sizeof(SBPropellerState);
}

void SB_Propeller_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void SB_Propeller_hitDetect(GameObject* obj) {
    if (obj->anim.romDefNo != SB_PROPELLER_SEQ_ID) {
        return;
    }
    obj->anim.rotZ = gSbPropellerObject->anim.rotZ;
}

void SB_Propeller_update(GameObject* obj) {
    int galleonStage;
    int galleonPhase;
    int cameraState;
    int parentTimer;
    int smokeCount;
    int frameIndex;
    GameObject* hitObjectAddress;
    SBPropellerState* state;
    PartFxSpawnParams spawnParams;

    state = obj->extra;
    galleonStage = SB_GALLEON_VTBL(obj->anim.parent)->getStage(obj->anim.parent);
    galleonPhase = SB_GALLEON_VTBL(obj->anim.parent)->getPhase(obj->anim.parent);
    if (state->health != 0 && galleonPhase < 6 && obj->anim.romDefNo != SB_PROPELLER_SEQ_ID) {
        Sfx_KeepAliveLoopedObjectSound(obj, SB_PROPELLER_SFX_LOOP);
    }
    cameraState = SB_Galleon_getCameraState((GameObject*)obj->anim.parent);
    if (cameraState < 2 && state->health <= 0) {
        state->smokeTimer = state->smokeTimer - timeDelta;
        if (state->smokeTimer <= 0.0f) {
            f32 scale;
            for (smokeCount = randomGetRange(10, 0x19), scale = 1.0f; smokeCount != 0; smokeCount--) {
                spawnParams.posX = obj->anim.worldPosX;
                spawnParams.posY = obj->anim.worldPosY;
                spawnParams.posZ = obj->anim.worldPosZ;
                spawnParams.scale = scale;
                (*gPartfxInterface)->spawnObject(obj, SB_PROPELLER_PARTFX_SMOKE, &spawnParams, 0x200001, -1, NULL);
            }
            state->smokeTimer = (f32)randomGetRange(0x5a, 0xf0);
        }
        if (galleonStage > 2 && obj->anim.bankIndex == 1) {
            spawnParams.scale = 2.5f;
            spawnParams.arg3 = 0xc0a;
            ObjPath_GetPointWorldPosition(obj, 0, &spawnParams.posX, &spawnParams.posY, &spawnParams.posZ, 0);
            spawnParams.posX = spawnParams.posX - obj->anim.worldPosX;
            spawnParams.posY = spawnParams.posY - obj->anim.worldPosY;
            spawnParams.posZ = spawnParams.posZ - obj->anim.worldPosZ;
            for (frameIndex = 0; frameIndex < framesThisStep; frameIndex++) {
                (*gPartfxInterface)->spawnObject(obj, SB_PROPELLER_PARTFX_DEBRIS, &spawnParams, 2, -1, NULL);
            }
        }
    }
    if (obj->anim.parent != NULL) {
        parentTimer = ((GameObject*)obj->anim.parent)->userData1;
        if (obj->anim.romDefNo != SB_PROPELLER_SEQ_ID && parentTimer < 4) {
            state->spinBlend = state->spinRate / 1600.0f;
            if (state->spinBlend < 0.0f) {
                state->spinBlend = -state->spinBlend;
            }
            if (state->spinBlend < 0.2f) {
                state->spinBlend = 0.2f;
            }
        }
        obj->userData1 = obj->userData1 - framesThisStep;
        if (obj->userData1 < 0) {
            obj->userData1 = 0;
        }
        if (galleonPhase == 1 && ObjHits_GetPriorityHit(obj, &hitObjectAddress, 0, 0) != 0 && obj->userData1 == 0 &&
            hitObjectAddress != NULL && hitObjectAddress != Obj_GetPlayerObject() &&
            hitObjectAddress->anim.romDefNo != SB_PROPELLER_SEQ_ID &&
            hitObjectAddress->anim.romDefNo != SB_OTHER_SEQ_ID &&
            (obj->userData1 = 0x14, obj->anim.parent != NULL) && (galleonStage == 2 || galleonStage == 5) &&
            obj->anim.romDefNo == SB_PROPELLER_SEQ_ID) {
            Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
            Sfx_PlayFromObject(obj, SB_PROPELLER_SFX_HIT);
            state->health -= 1;
            if (state->health <= 0) {
                state->health = 0;
                SB_GALLEON_VTBL(obj->anim.parent)->onPartDestroyed(obj->anim.parent);
                ObjHits_DisableObject(obj);
                obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
                spawnExplosion(obj, 100.0f, 1, 1, 1, 0, 1, 1, 0);
                Sfx_PlayFromObject(obj, SB_PROPELLER_SFX_DESTROYED);
            }
        }
        if (obj->userData1 == 0) {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 6;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->objectHitMask = 0x10;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->skeletonHitMask = 0x10;
        } else {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->objectPairPriority = 0;
        }
        obj->anim.rotZ = -(state->spinRate * timeDelta - (f32)obj->anim.rotZ);
    }
}

void SB_Propeller_init(GameObject* obj, SBPropellerPlacementView* placement) {
    u32 randVal;
    SBPropellerState* state;

    state = obj->extra;
    randVal = randomGetRange(0x5a, 0xf0);
    state->smokeTimer = (f32)(s32)randVal;
    state->spinBlend = 1.0f;
    state->spinRate = 1200;
    state->health = 4;
    obj->anim.bankIndex = (s8)placement->modelBankIndex;
    if (obj->anim.romDefNo != SB_PROPELLER_SEQ_ID) {
        gSbPropellerObject = obj;
    }
}

ObjectDescriptor gSB_PropellerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SB_Propeller_init,
    (ObjectDescriptorCallback)SB_Propeller_update,
    (ObjectDescriptorCallback)SB_Propeller_hitDetect,
    (ObjectDescriptorCallback)SB_Propeller_render,
    0,
    0,
    SB_Propeller_getExtraSize,
};
