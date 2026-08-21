/*
 * SH_Beacon (DLL 0x1B3) - the SnowHorn beacon / brazier the player lights.
 *
 * mode (ShBeaconState.mode): 0 = unlit, 1 = lit, 2 = igniting. While
 * unlit it waits for the FireWeed inventory event; igniting spawns its
 * SH_BeaconTw child object (runtime object ID 0x55), runs the ignite sequence,
 * and ticks the flame/fade effects through objfx_spawnPulseBurst. Once lit it
 * loops the fire sfx and sets its progress game bit. The placement carries the
 * lit/ignite game-bit ids.
 */
#include "dlls/objects/435_SH_Beacon.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/game_ui_interface.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/objhits.h"

/* Active EN OBJINDEX maps runtime object ID 0x55 to SH_BeaconTw. */
#define SH_BEACON_TWINKLE_OBJECT_ID  0x55
#define SH_BEACON_TWINKLE_SETUP_SIZE 0x20

f32 gShBeaconHitEffectCooldown;

int sh_beacon_sequenceCallback(GameObject* obj) {
    ShBeaconState* state = obj->extra;
    state->pulseTimer = state->pulseTimer + timeDelta;
    if (state->pulseTimer >= 20.0f) {
        state->pulseTimer = state->pulseTimer - 20.0f;
        if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
            objfx_spawnPulseBurst(obj, obj->anim.rootMotionScale, 0, 2, 0, NULL);
        }
    }
    return 0;
}

int sh_beacon_resetFadeTimerCallback(GameObject* obj) {
    ((ShBeaconState*)obj->extra)->fadeTimer = 6.0f;
    return 1;
}

int sh_beacon_getExtraSize(void) {
    return sizeof(ShBeaconState);
}

void sh_beacon_free(GameObject* obj, int keepChild) {
    ShBeaconState* state = obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    if (keepChild == 0) {
        GameObject* twinkleObject = state->twinkleObject;
        if (twinkleObject != NULL && (twinkleObject->objectFlags & OBJECT_OBJFLAG_FREED) == 0) {
            Obj_FreeObject(twinkleObject);
        }
    }
}

void sh_beacon_update(GameObject* obj) {
    ShBeaconState* state;
    ShBeaconPlacement* placement;
    GameObject* tricky;
    ObjPlacement* twinklePlacement;
    int pulseMode;
    ShBeaconState* ignitingState;

    state = obj->extra;
    placement = (ShBeaconPlacement*)obj->anim.placementData;
    switch (state->mode) {
    case SH_BEACON_MODE_UNLIT:
        if (((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) &&
            ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_FireWeed_Count) != 0)) {
            gameBitDecrement(GAMEBIT_ITEM_FireWeed_Count);
            mainSetBits(placement->igniteGameBit, 1);
            if (Obj_CanSetupObject() != 0) {
                twinklePlacement = Obj_AllocObjectSetup(SH_BEACON_TWINKLE_SETUP_SIZE, SH_BEACON_TWINKLE_OBJECT_ID);
                twinklePlacement->posX = obj->anim.localPosX;
                twinklePlacement->posY = obj->anim.localPosY;
                twinklePlacement->posZ = obj->anim.localPosZ;
                twinklePlacement->color[0] = 2;
                twinklePlacement->color[1] = obj->anim.placement->color[1];
                twinklePlacement->color[3] = obj->anim.placement->color[3];
                state->twinkleObject = loadObjectAtObject(obj, twinklePlacement);
            }
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            state->mode = SH_BEACON_MODE_IGNITING;
        }
        /* fall through */
    case SH_BEACON_MODE_IGNITING:
        ignitingState = obj->extra;
        ignitingState->pulseTimer = ignitingState->pulseTimer + timeDelta;
        if (ignitingState->pulseTimer >= 20.0f) {
            ignitingState->pulseTimer = ignitingState->pulseTimer - 20.0f;
            if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                objfx_spawnPulseBurst(obj, obj->anim.rootMotionScale, 0, 2, 0, NULL);
            }
        }
        break;
    case SH_BEACON_MODE_LIT:
        if (state->flags.loopSoundActive == 0) {
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_forcecryslp11);
            state->flags.loopSoundActive = 1;
        }
        if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
            state->pulseModeTimer = state->pulseModeTimer + timeDelta;
            if (state->pulseModeTimer > 10.0f) {
                pulseMode = 2;
                state->pulseModeTimer = state->pulseModeTimer - 10.0f;
            } else {
                pulseMode = 0;
            }
            state->pulseSpawnTimer = state->pulseSpawnTimer + timeDelta;
            if (state->pulseSpawnTimer > 2.0f) {
                state->pulseSpawnTimer = state->pulseSpawnTimer - 2.0f;
                objfx_spawnPulseBurst(obj, obj->anim.rootMotionScale, 2, pulseMode, 0, NULL);
            }
        }
        break;
    }
    if (state->mode != SH_BEACON_MODE_LIT) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (state->mode == SH_BEACON_MODE_IGNITING) {
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 8);
        } else if ((state->mode == SH_BEACON_MODE_UNLIT) && (mainGetBit(GAMEBIT_ITEM_FireWeed_Count) == 0)) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        } else {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        tricky = getTrickyObject();
        if ((tricky != NULL) && ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)) {
            TRICKY_INTERFACE(tricky)->sideCommandEnable(tricky, obj, TRICKY_COMMAND_KIND_PRIORITY, 4);
        }
    } else {
        if ((mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got) != 0) || (placement->litGameBit != GAMEBIT_Always1)) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        } else {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
    if (state->fadeTimer > 0.0f) {
        state->fadeTimer = state->fadeTimer - timeDelta;
        if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
            objfx_spawnPulseBurst(obj, 0.6f * obj->anim.rootMotionScale, 3, 0, 0, NULL);
        }
        if ((state->fadeTimer <= 0.0f) && (state->mode == SH_BEACON_MODE_IGNITING)) {
            state->mode = SH_BEACON_MODE_LIT;
            mainSetBits(placement->litGameBit, 1);
            if ((mainGetBit(GAMEBIT_SH_FireWeed_190) != 0) && (mainGetBit(GAMEBIT_SH_FireWeed_191) != 0) &&
                (mainGetBit(GAMEBIT_SH_FireWeed_192) != 0)) {
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            } else {
                Sfx_PlayFromObject(0, SFXTRIG_sc_menuups16k_409);
            }
        }
    }
    ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, SFXTRIG_swdtest222,
                                              &gShBeaconHitEffectCooldown);
}

void sh_beacon_init(GameObject* obj, const ShBeaconPlacement* placement) {
    ShBeaconState* state;
    ObjPlacement* twinklePlacement;

    state = obj->extra;
    obj->anim.rotX = (s16)((s32)placement->rotXByte << 8);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HIDDEN);

    state->mode = mainGetBit(placement->litGameBit);
    if (state->mode == SH_BEACON_MODE_UNLIT) {
        if (mainGetBit(placement->igniteGameBit) != 0) {
            state->mode = SH_BEACON_MODE_IGNITING;
        }
    }

    if (state->mode != SH_BEACON_MODE_UNLIT && Obj_CanSetupObject() != 0) {
        twinklePlacement = Obj_AllocObjectSetup(SH_BEACON_TWINKLE_SETUP_SIZE, SH_BEACON_TWINKLE_OBJECT_ID);
        twinklePlacement->posX = obj->anim.localPosX;
        twinklePlacement->posY = obj->anim.localPosY;
        twinklePlacement->posZ = obj->anim.localPosZ;
        twinklePlacement->color[0] = 2;
        twinklePlacement->color[1] = obj->anim.placement->color[1];
        twinklePlacement->color[3] = obj->anim.placement->color[3];
        state->twinkleObject = loadObjectAtObject(obj, twinklePlacement);
    }

    obj->animEventCallback = sh_beacon_sequenceCallback;
}

ObjectDescriptor gSH_BeaconObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)sh_beacon_init,
    (ObjectDescriptorCallback)sh_beacon_update,
    0,
    0,
    (ObjectDescriptorCallback)sh_beacon_free,
    0,
    sh_beacon_getExtraSize,
};
