#include "dlls/objects/283_Landed_Arwi.h"

#include "dlls/objects/284.h"
#include "main/dll/ARW/dll_029D_arwarwinggu.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/loaded_file_flags.h"
#include "main/mapEvent.h"
#include "main/map_load.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/objtype.h"
#include "main/obj_trigger.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"

#define LANDED_ARWING_TARGET_OBJECT_GROUP     0xF
#define LANDED_ARWING_CHILD_OBJECT_SETUP_SIZE 0x24
#define LANDED_ARWING_GADGET_OBJECT_ID        0x606
#define LANDED_ARWING_DEBRIS_OBJECT_ID        0x259
#define LANDED_ARWING_PATH_EFFECT_COUNT       5
#define LANDED_ARWING_GADGET_TEXTURE_FRAME    0xAF
#define LANDED_ARWING_GAME_BIT_NONE           -1
#define LANDED_ARWING_DAMAGE_TEXTURE_NONE     0
#define LANDED_ARWING_DAMAGE_TEXTURE_FIRST    0x100
#define LANDED_ARWING_DAMAGE_TEXTURE_SECOND   0x200

enum {
    LANDED_ARWING_SEQUENCE_STATE_DIRECT = 0,
    LANDED_ARWING_SEQUENCE_STATE_TRIGGER = 1,
    LANDED_ARWING_SEQUENCE_STATE_CONFIRM = 2,
};

enum {
    LANDED_ARWING_REACTION_SPAWN_DEBRIS = 0,
    LANDED_ARWING_REACTION_DAMAGE_NEAREST = 1,
    LANDED_ARWING_REACTION_JITTER = 2,
};

typedef struct LandedArwingFxPoint {
    f32 scale;
    u8 pathPoint;
    u8 mode;
    u8 mask;
    u8 pad;
} LandedArwingFxPoint;

typedef struct LandedArwingFxScratch {
    u8 effectData[12];
    f32 x;
    f32 y;
    f32 z;
} LandedArwingFxScratch;

STATIC_ASSERT(offsetof(LandedArwingFxPoint, scale) == 0x0);
STATIC_ASSERT(offsetof(LandedArwingFxPoint, pathPoint) == 0x4);
STATIC_ASSERT(offsetof(LandedArwingFxPoint, mode) == 0x5);
STATIC_ASSERT(offsetof(LandedArwingFxPoint, mask) == 0x6);
STATIC_ASSERT(offsetof(LandedArwingFxPoint, pad) == 0x7);
STATIC_ASSERT(sizeof(LandedArwingFxPoint) == 0x8);

STATIC_ASSERT(offsetof(LandedArwingFxScratch, effectData) == 0x0);
STATIC_ASSERT(offsetof(LandedArwingFxScratch, x) == 0xC);
STATIC_ASSERT(offsetof(LandedArwingFxScratch, y) == 0x10);
STATIC_ASSERT(offsetof(LandedArwingFxScratch, z) == 0x14);
STATIC_ASSERT(sizeof(LandedArwingFxScratch) == 0x18);

extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BC4;

LandedArwingFxPoint gLandedArwingPathFxTable[] = {
    {0.1f, 1, 7, 0x20, 0}, {0.1f, 2, 7, 0x20, 0}, {0.1f, 3, 8, 0x20, 0}, {0.1f, 4, 9, 0x20, 0}, {0.1f, 5, 6, 0x10, 0},
};

void landed_arwing_renderPathEffects(GameObject* obj) {
    LandedArwingObjectState* state;
    u8 effectIndex;
    LandedArwingFxScratch scratch;
    f32 zero = 0.0f;

    state = obj->extra;
    if (state->pathEffectsEnabled != 0) {
        effectIndex = 0;
        while (effectIndex < LANDED_ARWING_PATH_EFFECT_COUNT) {
            ObjPath_GetPointWorldPosition(obj, gLandedArwingPathFxTable[effectIndex].pathPoint, &scratch.x, &scratch.y,
                                          &scratch.z, 0);
            scratch.x -= obj->anim.localPosX;
            scratch.y -= obj->anim.localPosY;
            scratch.z -= obj->anim.localPosZ;
            objfx_spawnMaskedHitEffect(obj, obj->anim.rootMotionScale * gLandedArwingPathFxTable[effectIndex].scale, 4,
                                       gLandedArwingPathFxTable[effectIndex].mode,
                                       gLandedArwingPathFxTable[effectIndex].mask, scratch.effectData);
            effectIndex++;
        }
    }

    if (state->path6EffectStrength != zero) {
        ObjPath_GetPointWorldPosition(obj, 6, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= obj->anim.localPosX;
        scratch.y -= obj->anim.localPosY;
        scratch.z -= obj->anim.localPosZ;
        objfx_spawnLightPulse(obj, 0.7f, 4, 0, 0, state->path6EffectStrength, scratch.effectData);
    }

    if (state->path8EffectStrength != zero) {
        ObjPath_GetPointWorldPosition(obj, 8, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= obj->anim.localPosX;
        scratch.y -= obj->anim.localPosY;
        scratch.z -= obj->anim.localPosZ;
        objfx_spawnLightPulse(obj, 0.7f, 4, 0, 0, state->path8EffectStrength, scratch.effectData);
    }

    if (state->path7EffectStrength != zero) {
        ObjPath_GetPointWorldPosition(obj, 7, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= obj->anim.localPosX;
        scratch.y -= obj->anim.localPosY;
        scratch.z -= obj->anim.localPosZ;
        objfx_spawnLightPulse(obj, 0.7f, 4, 0, 0, state->path7EffectStrength, scratch.effectData);
    }
}

int landed_arwing_getExtraSize(void) {
    return sizeof(LandedArwingObjectState);
}

void landed_arwing_free(GameObject* obj) {
    LandedArwingObjectState* state = obj->extra;
    if (state->childObject != NULL) {
        Obj_FreeObject(state->childObject);
        ObjLink_DetachChild(obj, state->childObject);
    }
}

static void landed_arwing_runTargetSequence(GameObject* obj) {
    GameObject* nearest;
    LandedArwingPlacement* placement = (LandedArwingPlacement*)obj->anim.placementData;

    nearest = objGetNearestTypeTo(LANDED_ARWING_TARGET_OBJECT_GROUP, obj, NULL);
    if (obj->anim.mapEventSlot == 0xD && mainGetBit(GAMEBIT_Tricky_SaidGoodBye) != 0) {
        nearest->anim.localPosY += 20.0f;
        (*gObjectTriggerInterface)->runSequence(2, nearest, -1);
    } else {
        (*gObjectTriggerInterface)->runSequence(1, nearest, -1);
    }
    mainSetBits(placement->triggerGameBit, 0);
}

void landed_arwing_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        landed_arwing_renderPathEffects(obj);
    }
}

ObjectDescriptor gLanded_ArwingObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)landed_arwing_init,
    (ObjectDescriptorCallback)landed_arwing_update,
    0,
    (ObjectDescriptorCallback)landed_arwing_render,
    (ObjectDescriptorCallback)landed_arwing_free,
    0,
    landed_arwing_getExtraSize,
};

int Landed_Arwing_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int eventIndex;
    LandedArwingPlacement* placement;
    LandedArwingObjectState* state;
    int ident;
    GameObject* child;

    placement = (LandedArwingPlacement*)obj->anim.placementData;
    state = obj->extra;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        switch (animUpdate->eventIds[eventIndex]) {
        case 2:
        case 0x65:
            ident = placement->base.ident;
            switch (ident) {
            case 0x43775:
                loadMapAndParent(0x29);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x29), 0);
                break;
            case 0x451B9:
                if ((*gMapEventInterface)->getMapAct(0xD) == 2) {
                    loadMapAndParent(0xB);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0xB), 0);
                } else {
                    loadMapAndParent(0x29);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x29), 0);
                }
                break;
            case 0x49F5A:
                loadMapAndParent(0x26);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xB), 1);
                break;
            case 0x4CD65:
                loadMapAndParent(0x41);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x41), 0);
                lockLevel(mapGetDirIdx(0xB), 1);
                break;
            default:
                loadMapAndParent(0x29);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x29), 0);
                break;
            }
            break;
        case 3:
        case 0x64:
            ident = placement->base.ident;
            switch (ident) {
            case 0x43775:
                unlockLevel(0, 0, 1);
                mapUnload(mapGetDirIdx(7), 0x3F3C);
                break;
            case 0x49F5A:
                (*gMapEventInterface)->setObjGroupStatus(0xB, 4, 0);
                break;
            case 0x451B9:
                if ((*gMapEventInterface)->getMapAct(0xD) == 2) {
                    unlockLevel(0, 0, 1);
                    mapUnload(mapGetDirIdx(0xD), 0x3F3F);
                    (*gMapEventInterface)->setObjGroupStatus(0xD, 0xA, 0);
                    (*gMapEventInterface)->setObjGroupStatus(0xD, 0xB, 0);
                    (*gMapEventInterface)->setObjGroupStatus(0xD, 0xE, 0);
                }
                break;
            case 0x4CD65:
                unlockLevel(0, 0, 1);
                mapUnload(mapGetDirIdx(0xB), 0x3F00);
                break;
            }
            break;
        case 5:
            ident = placement->base.ident;
            switch (ident) {
            case 0x43775:
            case 0x49F5A:
                setLoadedFileFlags_blocks1();
                break;
            case 0x451B9:
                if ((*gMapEventInterface)->getMapAct(0xD) == 2) {
                    setLoadedFileFlags_blocks1();
                }
                break;
            }
            break;
        case 6:
            ident = placement->base.ident;
            switch (ident) {
            case 0x43775:
            case 0x49F5A:
                clearLoadedFileFlags_blocks1();
                break;
            case 0x451B9:
                if ((*gMapEventInterface)->getMapAct(0xD) == 2) {
                    clearLoadedFileFlags_blocks1();
                }
                break;
            }
            break;
        case 7:
        case 0x66:
            ident = placement->base.ident;
            switch (ident) {
            case 0x451B9:
                if ((*gMapEventInterface)->getMapAct(0xD) == 2) {
                    (*gMapEventInterface)->setMapAct(0xB, 5);
                    warpToMap(0x4E, 0);
                }
                break;
            case 0x49F5A:
                warpToMap(0x32, 0);
                break;
            case 0x4CD65:
                warpToMap(0x7F, 0);
                (*gMapEventInterface)->setMapAct(0x41, 2);
                break;
            }
            break;
        case 0xA:
            state->pathEffectsEnabled = 1;
            break;
        case 0xB:
            state->pathEffectsEnabled = 0;
            break;
        case 0xC:
            state->path7EffectStrength = 0.0f;
            break;
        case 0xD:
            state->path7EffectStrength = 0.2f;
            break;
        case 0xE:
            state->path7EffectStrength = 0.4f;
            break;
        case 0xF:
            state->path7EffectStrength = 0.6f;
            break;
        case 0x10:
            state->path8EffectStrength = 0.0f;
            break;
        case 0x11:
            state->path8EffectStrength = 0.2f;
            break;
        case 0x12:
            state->path8EffectStrength = 0.4f;
            break;
        case 0x13:
            state->path8EffectStrength = 0.6f;
            break;
        case 0x14:
            state->path6EffectStrength = 0.0f;
            break;
        case 0x15:
            state->path6EffectStrength = 0.2f;
            break;
        case 0x16:
            state->path6EffectStrength = 0.4f;
            break;
        case 0x17:
            state->path6EffectStrength = 0.6f;
            break;
        case 0x18:
            child = state->childObject;
            if (child != NULL) {
                child->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            }
            break;
        case 0x19:
            child = state->childObject;
            if (child != NULL) {
                child->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
            break;
        }
    }
    return 0;
}

void landed_arwing_update(GameObject* obj) {
    LandedArwingObjectState* state;
    GameObject* player;
    GameObject* child;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (state->childObject == NULL) {
        if (Obj_IsLoadingLocked() != 0) {
            child = (GameObject*)objSetupObject(
                Obj_AllocObjectSetup(LANDED_ARWING_CHILD_OBJECT_SETUP_SIZE, LANDED_ARWING_GADGET_OBJECT_ID), 4, -1, -1,
                0);
            state->childObject = child;
            if (state->childObject != NULL) {
                ObjLink_AttachChild(obj, state->childObject, 0);
                arwarwinggu_setTextureFrame(state->childObject, LANDED_ARWING_GADGET_TEXTURE_FRAME);
                state->childObject->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }

    if (state->childObject != NULL) {
        arwarwinggu_applyTextureFrame(state->childObject);
    }

    if (player != NULL && playerGetFocusObject(player) != NULL) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    switch (state->sequenceState) {
    case LANDED_ARWING_SEQUENCE_STATE_DIRECT:
        if (ObjTrigger_IsSet(obj) != 0) {
            landed_arwing_runTargetSequence(obj);
        }
        break;
    case LANDED_ARWING_SEQUENCE_STATE_TRIGGER:
        if (ObjTrigger_IsSet(obj) != 0) {
            state->sequenceState = LANDED_ARWING_SEQUENCE_STATE_CONFIRM;
            showFuelCellTokenConfirmMenu();
        }
        ObjHits_PollPriorityHitEffectWithCooldown(obj, STAFF_ACTIVATED_HIT_EFFECT_MODE, STAFF_ACTIVATED_HIT_EFFECT_RED,
                                                  STAFF_ACTIVATED_HIT_EFFECT_GREEN, STAFF_ACTIVATED_HIT_EFFECT_BLUE,
                                                  STAFF_ACTIVATED_HIT_EFFECT_SFX, &state->sequenceHitCooldown);
        break;
    case LANDED_ARWING_SEQUENCE_STATE_CONFIRM:
        if (pauseMenuGetTokenConfirmFlag() != 0) {
            landed_arwing_runTargetSequence(obj);
        } else {
            state->sequenceState = LANDED_ARWING_SEQUENCE_STATE_TRIGGER;
        }
        break;
    }
}

void landed_arwing_init(GameObject* obj, LandedArwingPlacement* placement) {
    LandedArwingObjectState* state = obj->extra;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    state->sequenceState = LANDED_ARWING_SEQUENCE_STATE_TRIGGER;
    if (mainGetBit(placement->triggerGameBit) == 0) {
        unlockLevel(0, 0, 1);
    }
    obj->animEventCallback = Landed_Arwing_SeqFn;
}

void landed_arwing_updateHitReaction(GameObject* obj, LandedArwingHitReactionState* state) {
    int spawnIndex;
    LandedArwingHitReactionState* otherState;
    StaffActivatedPlacement* placement;
    ObjPlacement* setup;
    GameObject* other;
    f32 range;
    f32 yOffset;
    ObjAnimEventList events;

    placement = (StaffActivatedPlacement*)obj->anim.placementData;
    if (!state->flags.damaged || (state->flags.impactHandled && state->hitStarted == 0u)) {
        return;
    }
    if (state->hitStarted != 0) {
        obj->anim.rotY = 0;
        obj->anim.rotZ = 0;
        if (obj->anim.currentMoveProgress >= lbl_803E3BBC && !state->flags.reactionDone) {
            if (placement->reactionCompleteGameBit > 0) {
                mainSetBits(placement->reactionCompleteGameBit, 1);
            }

            switch (placement->hitReactionType) {
            case LANDED_ARWING_REACTION_SPAWN_DEBRIS:
                if (Obj_IsLoadingLocked() != 0) {
                    spawnIndex = 0;
                    yOffset = lbl_803E3BB8;
                    while (spawnIndex < placement->debrisCount) {
                        setup =
                            Obj_AllocObjectSetup(LANDED_ARWING_CHILD_OBJECT_SETUP_SIZE, LANDED_ARWING_DEBRIS_OBJECT_ID);
                        setup->posX = obj->anim.localPosX;
                        setup->posY = yOffset + obj->anim.localPosY;
                        setup->posZ = obj->anim.localPosZ;
                        setup->color[0] = 1;
                        objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        spawnIndex++;
                    }
                }
                break;
            case LANDED_ARWING_REACTION_DAMAGE_NEAREST:
                range = lbl_803E3BC0;
                other = objGetNearestTypeTo(STAFF_ACTIVATED_OBJECT_GROUP, obj, &range);
                if (other != NULL) {
                    otherState = other->extra;
                    if (((StaffActivatedPlacement*)other->anim.placementData)->siblingGameBit > 0) {
                        mainSetBits(((StaffActivatedPlacement*)other->anim.placementData)->siblingGameBit, 1);
                    }
                    otherState->flags.damaged = 1;
                }
                break;
            case LANDED_ARWING_REACTION_JITTER:
                break;
            }
            state->hitStarted = 0;
            state->flags.reactionDone = 1;
        }
        state->flags.impactHandled = 1;
        state->animationStepScale = lbl_803E3BC4;
    } else {
        if (placement->hitReactionType == LANDED_ARWING_REACTION_JITTER) {
            obj->anim.rotY = randomGetRange(-200, 200);
            obj->anim.rotZ = randomGetRange(-200, 200);
        }
        ObjHits_PollPriorityHitEffectWithCooldown(obj, STAFF_ACTIVATED_HIT_EFFECT_MODE, STAFF_ACTIVATED_HIT_EFFECT_RED,
                                                  STAFF_ACTIVATED_HIT_EFFECT_GREEN, STAFF_ACTIVATED_HIT_EFFECT_BLUE,
                                                  STAFF_ACTIVATED_HIT_EFFECT_SFX, &state->hitEffectCooldown);
    }
    ObjAnim_AdvanceCurrentMove(obj, state->animationStepScale, timeDelta, &events);
}

void landed_arwing_updateDamageTexture(GameObject* obj, LandedArwingHitReactionState* state) {
    StaffActivatedPlacement* placement;
    ObjTextureRuntimeSlot* texture;
    u32 bit;
    LandedArwingHitFlags* flags;

    placement = (StaffActivatedPlacement*)obj->anim.placementData;
    flags = &state->flags;
    if (placement->damageStateGameBit != LANDED_ARWING_GAME_BIT_NONE) {
        bit = mainGetBit(placement->damageStateGameBit);
        flags->damageStateGameBitSet = bit;
        bit = flags->damageStateGameBitSet;
        if (bit != 0 && placement->mode == STAFF_ACTIVATED_MODE_DAMAGE_SECOND) {
            flags->impactHandled = 1;
        } else if (bit == 0) {
            flags->impactHandled = 0;
        }
    }

    if (flags->damaged == 0) {
        if (placement->damagedGameBit != LANDED_ARWING_GAME_BIT_NONE && mainGetBit(placement->damagedGameBit) != 0) {
            flags->damaged = 1;
        }
    } else {
        if (placement->activeGameBit != LANDED_ARWING_GAME_BIT_NONE && mainGetBit(placement->activeGameBit) == 0) {
            flags->damaged = 0;
        }
    }

    texture = objFindTexture(obj, 0, 0);
    if (texture != NULL) {
        if (flags->damaged != 0) {
            if (flags->damageStateGameBitSet != 0) {
                texture->textureId = LANDED_ARWING_DAMAGE_TEXTURE_SECOND;
            } else {
                texture->textureId = LANDED_ARWING_DAMAGE_TEXTURE_FIRST;
            }
        } else {
            texture->textureId = LANDED_ARWING_DAMAGE_TEXTURE_NONE;
        }
    }
}
