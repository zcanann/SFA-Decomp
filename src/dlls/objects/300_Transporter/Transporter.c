/*
 * Warp-pad object: handles per-placement travel, progression gates, sequence
 * events, and environment restoration.
 */
#include "dlls/objects/300_Transporter.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/lightmap_render_control_api.h"
#include "main/loaded_file_flags.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/objprint_render_api.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/obj_trigger.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"

/* recurring shimmer emitted randomly across all warp-pulse stages */
#define WARPPAD_PARTFX_PULSE 0x7CA
/* surge burst emitted at the stage-2 transition and the stage-3 latch release */
#define WARPPAD_PARTFX_SURGE 0x7D2

#define WARP_PAD_A_BUTTON_ICON         0x1B
#define WARP_PAD_INTERACTION_DISTANCE  40.0f
#define WARP_PAD_PROXIMITY_DISTANCE_SQ 409600.0f
#define WARP_PAD_PULSE_RANDOM_LIMIT    0x1E0
#define WARP_PAD_PULSE_STAGE1_TIME     120.0f
#define WARP_PAD_PULSE_STAGE2_TIME     360.0f
#define WARP_PAD_PULSE_STAGE2_DURATION 240.0f
#define WARP_PAD_PULSE_STAGE3_TIME     420.0f
#define WARP_PAD_PULSE_END_TIME        480.0f
#define WARP_PAD_SURGE_SCALE_GROWTH    0.0009f
#define WARP_PAD_SURGE_SCALE_RELEASE   0.00036f

typedef enum TransporterSequenceId {
    TRANSPORTER_SEQUENCE_OUTBOUND = 0,
    TRANSPORTER_SEQUENCE_INBOUND = 1,
    TRANSPORTER_SEQUENCE_TUTORIAL = 2,
} TransporterSequenceId;


void Transporter_updateEffects(GameObject* obj) {
    TransporterState* state;
    GameObject* player;
    PartFxSpawnParams fx;
    u8 flags;
    u8 i;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    fx.position[0] = 0.0f;
    fx.position[1] = 55.0f;
    fx.position[2] = 0.0f;
    flags = state->flags;

    if ((flags & TRANSPORTER_FLAG_WARP_A) != 0) {
        if ((flags & TRANSPORTER_FLAG_WARP_B) != 0) {
            fx.arg2 = 0xC0E;
            fx.arg1 = 1;
        } else if ((flags & TRANSPORTER_FLAG_WARP_C) != 0) {
            fx.arg2 = 0xC7E;
            fx.arg1 = 2;
        } else {
            fx.arg2 = 0xC13;
            fx.arg1 = 0;
        }
    } else if ((flags & TRANSPORTER_FLAG_WARP_B) != 0) {
        if (vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < WARP_PAD_PROXIMITY_DISTANCE_SQ) {
            if (((state->flags & (TRANSPORTER_FLAG_DISABLED | TRANSPORTER_FLAG_ENABLE_GAMEBIT_OFF)) != 0) &&
                (state->countdownActive == 0)) {
                objfx_spawnArcedBurst(obj, 1, 0.75f, 2, 7, 100, 30.0f, 30.0f, 110.0f, &fx, 0);
            } else {
                objfx_spawnArcedBurst(obj, 1, 0.5f, 1, 6, 100, 30.0f, 30.0f, 110.0f, &fx, 0);
            }
        }
        fx.arg2 = 0xC0E;
        fx.arg1 = 1;
    } else if ((flags & TRANSPORTER_FLAG_WARP_C) != 0) {
        if (vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < WARP_PAD_PROXIMITY_DISTANCE_SQ) {
            if (((state->flags & (TRANSPORTER_FLAG_DISABLED | TRANSPORTER_FLAG_ENABLE_GAMEBIT_OFF)) != 0) &&
                (state->countdownActive == 0)) {
                objfx_spawnArcedBurst(obj, 1, 0.75f, 2, 7, 100, 30.0f, 30.0f, 110.0f, &fx, 0);
            } else {
                objfx_spawnArcedBurst(obj, 1, 0.5f, 5, 6, 100, 30.0f, 30.0f, 110.0f, &fx, 0);
            }
        }
        fx.arg2 = 0xC7E;
        fx.arg1 = 2;
    } else {
        if (vec3f_distanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < WARP_PAD_PROXIMITY_DISTANCE_SQ) {
            if (((state->flags & (TRANSPORTER_FLAG_DISABLED | TRANSPORTER_FLAG_ENABLE_GAMEBIT_OFF)) != 0) &&
                (state->countdownActive == 0)) {
                objfx_spawnArcedBurst(obj, 1, 0.75f, 2, 7, 100, 30.0f, 30.0f, 110.0f, &fx, 0);
            } else {
                objfx_spawnArcedBurst(obj, 1, 0.5f, 3, 6, 100, 30.0f, 30.0f, 110.0f, &fx, 0);
            }
        }
        fx.arg2 = 0xC13;
        fx.arg1 = 0;
    }

    if ((state->flags & TRANSPORTER_FLAG_PULSE_FX) != 0) {
        if (state->pulseTimer < WARP_PAD_PULSE_STAGE1_TIME) {
            if ((f32)(s32)randomGetRange(0, WARP_PAD_PULSE_RANDOM_LIMIT) < state->pulseTimer / 2.0f) {
                (*gPartfxInterface)->spawnEffect(obj, WARPPAD_PARTFX_PULSE, &fx, 2, -1, NULL);
            }
        } else if (state->pulseTimer < WARP_PAD_PULSE_STAGE2_TIME) {
            if ((f32)(s32)randomGetRange(0, WARP_PAD_PULSE_RANDOM_LIMIT) < state->pulseTimer / 3.0f) {
                (*gPartfxInterface)->spawnEffect(obj, WARPPAD_PARTFX_PULSE, &fx, 2, -1, NULL);
            }
            fx.effectParam = 0x28;
            fx.arg0 = 0;
            fx.scale = WARP_PAD_SURGE_SCALE_GROWTH *
                       ((state->pulseTimer - WARP_PAD_PULSE_STAGE1_TIME) / WARP_PAD_PULSE_STAGE2_DURATION);
            (*gPartfxInterface)->spawnEffect(obj, WARPPAD_PARTFX_SURGE, &fx, 2, -1, NULL);
            state->flags |= TRANSPORTER_FLAG_PULSE_LATCH;
        } else if (state->pulseTimer < WARP_PAD_PULSE_STAGE3_TIME) {
            if ((f32)(s32)randomGetRange(0, WARP_PAD_PULSE_RANDOM_LIMIT) < state->pulseTimer / 2.0f) {
                (*gPartfxInterface)->spawnEffect(obj, WARPPAD_PARTFX_PULSE, &fx, 2, -1, NULL);
            }
            if ((state->flags & TRANSPORTER_FLAG_PULSE_LATCH) != 0) {
                state->flags &= ~TRANSPORTER_FLAG_PULSE_LATCH;
                fx.effectParam = 0x46;
                fx.scale = WARP_PAD_SURGE_SCALE_RELEASE;
                for (i = 0xF; i != 0; i--) {
                    (*gPartfxInterface)->spawnEffect(obj, WARPPAD_PARTFX_SURGE, &fx, 2, -1, NULL);
                }
            }
        } else if (!(state->pulseTimer < WARP_PAD_PULSE_END_TIME)) {
            state->pulseTimer = 0.0f;
            state->flags &= ~TRANSPORTER_FLAG_PULSE_FX;
        }
        state->pulseTimer += timeDelta;
    }
}

void Transporter_updateInteraction(GameObject* obj) {
    TransporterPlacement* placement;
    TransporterState* state;
    GameObject* player;
    s16 gameBit;

    placement = (TransporterPlacement*)obj->anim.placement;
    state = obj->extra;
    gameBit = placement->enableGameBit;
    if (gameBit != TRANSPORTER_GAME_BIT_NONE) {
        if (mainGetBit(gameBit) != 0) {
            state->flags &= ~TRANSPORTER_FLAG_ENABLE_GAMEBIT_OFF;
        } else {
            state->flags |= TRANSPORTER_FLAG_ENABLE_GAMEBIT_OFF;
        }
    }

    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0) {
        setAButtonIcon(WARP_PAD_A_BUTTON_ICON);
        if (mainGetBit(GAMEBIT_SawWarpPad) == 0) {
            (*gObjectTriggerInterface)->runSequence(TRANSPORTER_SEQUENCE_TUTORIAL, (void*)obj, -1);
            mainSetBits(GAMEBIT_SawWarpPad, 1);
            return;
        }
    }

    player = Obj_GetPlayerObject();
    if (player == NULL) {
        return;
    }

    if ((state->triggerMode == TRANSPORTER_TRIGGER_PROXIMITY) && (state->countdownActive == 0) &&
        ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)) {
        if ((gArrivedWarpIndex > -1) && (Vec_xzDistance(&obj->anim.worldPosX, &Obj_GetPlayerObject()->anim.worldPosX) <
                                    WARP_PAD_INTERACTION_DISTANCE)) {
            (*gObjectTriggerInterface)->runSequence(TRANSPORTER_SEQUENCE_INBOUND, (void*)obj, -1);
            obj->userData1 = state->activateDelay;
            state->triggerMode = TRANSPORTER_TRIGGER_PROXIMITY;
            state->countdownActive = 1;
            gWarpArrivalTimer = 2;
        } else {
            gameBit = placement->enableGameBit;
            if (((gameBit == TRANSPORTER_GAME_BIT_NONE) ||
                 ((mainGetBit(gameBit) != 0) && ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0))) &&
                (ObjTrigger_IsSet(obj) != 0)) {
                (*gObjectTriggerInterface)->runSequence(TRANSPORTER_SEQUENCE_OUTBOUND, (void*)obj, -1);
                obj->userData1 = state->activateDelay;
                state->triggerMode = TRANSPORTER_TRIGGER_INTERACTION;
                state->countdownActive = 1;
            }
        }
    }

    if (state->countdownActive != 0) {
        if (obj->userData1 > 0) {
            obj->userData1 -= framesThisStep;
        } else {
            obj->userData1 = 0;
            state->countdownActive = 0;
        }
    }
    state->cooldownTimer -= timeDelta;
    if (state->cooldownTimer <= 0.0f) {
        state->cooldownTimer = 0.0f;
        state->unk0A = -1;
    }
}


/* Environment effects restored by animation event 8. */
#define TRANSPORTER_ENVFX_G0_A 0x224 /* mapIds 0x43F83 / 0x4977D */
#define TRANSPORTER_ENVFX_G0_B 0x223
#define TRANSPORTER_ENVFX_ENV  0x22E /* shared by G0 and G1 */
#define TRANSPORTER_ENVFX_SKY  0x218 /* shared by G0 and G1 */
#define TRANSPORTER_ENVFX_G1_A 0x217 /* mapIds 0x48506 / 0x4A533 */
#define TRANSPORTER_ENVFX_G1_B 0x216
#define TRANSPORTER_ENVFX_G1_C 0x84
#define TRANSPORTER_ENVFX_G1_D 0x8A
#define TRANSPORTER_ENVFX_G2_A 0x23A /* mapIds 0x4B666 / 0x4B667 */
#define TRANSPORTER_ENVFX_G2_B 0x23B
#define TRANSPORTER_ENVFX_G2_C 0x23E
#define TRANSPORTER_ENVFX_G3_A 0x247 /* mapIds 0x4670D / 0x4827E / 0x49267 */
#define TRANSPORTER_ENVFX_G3_B 0x248
#define TRANSPORTER_ENVFX_G4_A 0x238 /* ident 0x4CB6A */
#define TRANSPORTER_ENVFX_G4_B 0x239

#define TRANSPORTER_ACTIVATE_DELAY 400
#define TRANSPORTER_ROTATION_SHIFT 8

typedef enum TransporterSequenceEvent {
    TRANSPORTER_EVENT_WARP = 1,
    TRANSPORTER_EVENT_MAP_PROGRESS = 2,
    TRANSPORTER_EVENT_UNLOCK_LEVEL = 3,
    TRANSPORTER_EVENT_LOAD_BLOCKS = 5,
    TRANSPORTER_EVENT_CLEAR_BLOCKS = 6,
    TRANSPORTER_EVENT_PULSE_FX = 7,
    TRANSPORTER_EVENT_RESTORE_ENVIRONMENT = 8,
} TransporterSequenceEvent;


ObjectDescriptor gTransporterObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)Transporter_init,
    (ObjectDescriptorCallback)Transporter_update,
    (ObjectDescriptorCallback)Transporter_hitDetect,
    (ObjectDescriptorCallback)Transporter_render,
    0,
    0,
    Transporter_getExtraSize,
};

int Transporter_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int i;
    TransporterPlacement* placement = (TransporterPlacement*)obj->anim.placementData;
    TransporterState* state = obj->extra;
    int id;

    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
        case TRANSPORTER_EVENT_PULSE_FX:
            state->flags |= TRANSPORTER_FLAG_PULSE_FX;
            Sfx_PlayFromObject(obj, SFXTRIG_id_420);
            break;
        case TRANSPORTER_EVENT_MAP_PROGRESS:
            id = placement->base.ident;
            switch (id) {
            case 0x49C33:
                mainSetBits(GAMEBIT_SH_WarpStoneRelated0884, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 2, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 3, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 7, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 10, 1);
                (*gMapEventInterface)->setObjGroupStatus(10, 7, 0);
            case 0x48506:
            case 0x4977D:
                loadMapAndParent(7);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(7), 1);
                break;
            case 0x43F83:
                loadMapAndParent(0x21);
                lockLevel(mapGetDirIdx(0x21), 1);
                break;
            case 0x4A533:
                loadMapAndParent(0x28);
                lockLevel(mapGetDirIdx(0x28), 1);
                break;
            case 0xC5D:
                unlockLevel(mapGetDirIdx(0x21), 1, 0);
                break;
            case 0x47064:
                loadMapAndParent(0x1C);
                lockLevel(mapGetDirIdx(0x1C), 1);
                lockLevel(mapGetDirIdx(0x1B), 0);
                break;
            case 0x4800C:
                loadMapAndParent(0x22);
                lockLevel(mapGetDirIdx(0xD), 0);
                lockLevel(mapGetDirIdx(0x22), 1);
                break;
            case 0x48018:
                unlockLevel(mapGetDirIdx(0x22), 1, 0);
                mainSetBits(GAMEBIT_WC_ObjGroups, 0);
                (*gMapEventInterface)->setObjGroupStatus(0xD, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xD, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xD, 5, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xD, 10, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xD, 0xB, 1);
                mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 0);
                break;
            case 0x45DD6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(4), 0);
                break;
            case 0x2BA7:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x12), 0);
                lockLevel(mapGetDirIdx(0x1F), 1);
                loadMapAndParent(0x1F);
                break;
            case 0x46A40:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0xE), 0);
                lockLevel(mapGetDirIdx(0x20), 1);
                loadMapAndParent(0x20);
                break;
            case 0x4B666:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x32), 0);
                lockLevel(mapGetDirIdx(0x15), 1);
                loadMapAndParent(0x15);
                break;
            case 0x497F4:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                lockLevel(mapGetDirIdx(0x27), 1);
                loadMapAndParent(0x27);
                break;
            case 0x4CDE6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            }
            break;
        case TRANSPORTER_EVENT_UNLOCK_LEVEL:
            switch (placement->base.ident) {
            case 0x47064:
                unlockLevel(0, 0, 1);
                break;
            }
            break;
        case TRANSPORTER_EVENT_LOAD_BLOCKS:
            switch (placement->base.ident) {
            case 0x47064:
                setLoadedFileFlags_blocks1();
                break;
            }
            break;
        case TRANSPORTER_EVENT_CLEAR_BLOCKS:
            switch (placement->base.ident) {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            break;
        case TRANSPORTER_EVENT_WARP:
            switch (placement->base.ident) {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            warpToMap(placement->warpId, 0);
            break;
        case TRANSPORTER_EVENT_RESTORE_ENVIRONMENT:
            id = placement->base.ident;
            switch (id) {
            case 0x43F83:
            case 0x4977D:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G0_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G0_B, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_ENV, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_SKY, 0);
                setDrawCloudsAndLights(0);
                skySetSlotFlag80(1, 1);
                skySetLightIndex(0, 0.0f);
                break;
            case 0x48506:
            case 0x4A533:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_B, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_ENV, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_SKY, 0);
                setDrawCloudsAndLights(1);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_C, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G1_D, 0);
                skySetSlotFlag80(1, 0);
                skySetLightIndex(0, 0.0f);
                break;
            case 0x4B666:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_B, 0);
                break;
            case 0x4B667:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G2_B, 0);
                (*gMapEventInterface)->setObjGroupStatus(0x15, 2, 1);
                getEnvfxActImmediately(0, 0, TRANSPORTER_ENVFX_G2_C, 0);
                skySetLightIndex(1, 0.0f);
                break;
            case 0x4670D:
            case 0x4827E:
            case 0x49267:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G3_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G3_B, 0);
                Rcp_DisableHeatEffect();
                mainSetBits(GAMEBIT_VFP_EnvironmentRelated0EF6, 1);
                break;
            case 0x4CB6A:
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G4_A, 0);
                getEnvfxActImmediately(obj, obj, TRANSPORTER_ENVFX_G4_B, 0);
                skySetSlotFlag80(1, 1);
                skySetLightIndex(0, 0.0f);
            case 0x4CB84:
                mainSetBits(GAMEBIT_VFP_EnvironmentRelated0EF6, 0);
                break;
            }
            break;
        }
    }
    Transporter_updateEffects(obj);
    return 0;
}

int Transporter_getExtraSize(void) {
    return sizeof(TransporterState);
}

void Transporter_render(void) {
}

void Transporter_hitDetect(int obj) {
    register int self = obj;
    register TransporterPlacement* placement = (TransporterPlacement*)((GameObject*)self)->anim.placementData;
    register TransporterState* state = ((GameObject*)self)->extra;

    if (gArrivedWarpIndex > -1) {
        ((GameObject*)self)->anim.resetHitboxFlags &= ~(INTERACT_FLAG_DISABLED | INTERACT_FLAG_PROMPT_SUPPRESSED);
        state->flags |= TRANSPORTER_FLAG_INTERACTIVE;
        if (((GameObject*)self)->anim.hitVolumeTransforms != NULL) {
            objUpdateHitVolumeTransforms((GameObject*)self);
        }
        return;
    }

    if (placement->warpId != TRANSPORTER_WARP_ID_NONE && (state->flags & TRANSPORTER_FLAG_DISABLED) == 0) {
        if (state->triggerMode != 0 || state->countdownActive != 0) {
            ((GameObject*)self)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            state->flags &= ~TRANSPORTER_FLAG_INTERACTIVE;
        } else if (placement->enableGameBit != TRANSPORTER_GAME_BIT_NONE && mainGetBit(placement->enableGameBit) == 0) {
            ((GameObject*)self)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            ((GameObject*)self)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
            state->flags &= ~TRANSPORTER_FLAG_INTERACTIVE;
        } else {
            ((GameObject*)self)->anim.resetHitboxFlags &= ~(INTERACT_FLAG_DISABLED | INTERACT_FLAG_PROMPT_SUPPRESSED);
            state->flags |= TRANSPORTER_FLAG_INTERACTIVE;
        }
        if (((GameObject*)self)->anim.hitVolumeTransforms != NULL) {
            objUpdateHitVolumeTransforms((GameObject*)self);
        }
        return;
    }

    if ((state->flags & TRANSPORTER_FLAG_WARP_A) != 0) {
        ((GameObject*)self)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    } else {
        ((GameObject*)self)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        ((GameObject*)self)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    state->flags &= ~TRANSPORTER_FLAG_INTERACTIVE;
}

void Transporter_update(GameObject* obj) {
    register int self = (int)obj;
    register TransporterPlacement* placement = (TransporterPlacement*)((GameObject*)self)->anim.placementData;
    if (placement->warpId != TRANSPORTER_WARP_ID_NONE) {
        Transporter_updateInteraction((GameObject*)self);
    }
    Transporter_updateEffects((GameObject*)self);
}

void Transporter_init(GameObject* obj, TransporterPlacement* placement) {
    TransporterState* state;
    int id;

    state = obj->extra;
    state->activateDelay = TRANSPORTER_ACTIVATE_DELAY;
    state->flags = 0;
    obj->anim.rotX = (s16)((u16)(placement->rotXHigh << TRANSPORTER_ROTATION_SHIFT));
    obj->userData1 = 0;
    obj->animEventCallback = Transporter_sequenceCallback;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;

    id = placement->base.ident;
    switch (id) {
    case 0x4670D:
    case 0x4827E:
    case 0x49267:
    case 0x4CB6A:
    case 0x4CB84:
        state->flags |= TRANSPORTER_FLAG_WARP_A | TRANSPORTER_FLAG_DISABLED | TRANSPORTER_FLAG_WARP_B;
        break;
    case 0x48506:
    case 0x45753:
    case 0x463C0:
    case 0x45DD6:
    case 0x4977D:
    case 0x49C33:
    case 0x4B666:
    case 0x4B667:
        state->flags |= TRANSPORTER_FLAG_WARP_B;
        break;
    case 0x4C986:
        state->flags |= TRANSPORTER_FLAG_DISABLED | TRANSPORTER_FLAG_WARP_C;
        break;
    case 0x47064:
        state->flags |= TRANSPORTER_FLAG_WARP_C;
        break;
    case 0x43F83:
        if (mainGetBit(GAMEBIT_K1_SPIRIT_COLLECTED) != 0 || mainGetBit(GAMEBIT_K1_SPIRIT_DEPOSITED) != 0 ||
            mainGetBit(GAMEBIT_K1_ReturnPadGuard) != 0) {
            state->flags |= TRANSPORTER_FLAG_DISABLED;
        }
        break;
    case 0x2BA7:
        if (mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit2_Used) != 0 ||
            mainGetBit(GAMEBIT_WM_SpiritPlace2Ready) != 0) {
            state->flags |= TRANSPORTER_FLAG_DISABLED;
        }
        break;
    case 0x46A40:
        if (mainGetBit(GAMEBIT_ITEM_SpiritTestFear_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit3_Released) != 0 ||
            mainGetBit(GAMEBIT_WM_SpiritPlace3Ready) != 0) {
            state->flags |= TRANSPORTER_FLAG_DISABLED;
        }
        break;
    case 0x497F4:
        if (mainGetBit(GAMEBIT_ITEM_SpiritTestStrength_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit4_Used) != 0 ||
            mainGetBit(GAMEBIT_WM_SpiritPlace4Ready) != 0) {
            state->flags |= TRANSPORTER_FLAG_DISABLED;
        }
        break;
    case 0x4800C:
        if (mainGetBit(GAMEBIT_ITEM_Spirit5_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit5_Released) != 0 ||
            mainGetBit(GAMEBIT_WM_SpiritPlace5Ready) != 0) {
            state->flags |= TRANSPORTER_FLAG_DISABLED;
        }
        break;
    case 0x4A533:
        if (mainGetBit(GAMEBIT_ITEM_Spirit6_Got) != 0 || mainGetBit(GAMEBIT_ITEM_Spirit6_Released) != 0 ||
            mainGetBit(GAMEBIT_WM_SpiritPlace6Ready) != 0) {
            state->flags |= TRANSPORTER_FLAG_DISABLED;
        }
        break;
    }

    if ((state->flags & TRANSPORTER_FLAG_WARP_A) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    }
}

