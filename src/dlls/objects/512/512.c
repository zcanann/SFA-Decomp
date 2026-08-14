/*
 * DLL 0x0200 implements map-act-specific interaction, sequence, and wandering
 * behaviors.
 */
#include "dlls/objects/512.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "game/objects/object.h"
#include "main/audio/sfx_ids.h"
#include "main/debug.h"
#include "main/dll/player_api.h"
#include "main/dll/player_status.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/objHitReact.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/pad_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

typedef struct Dll200ItemSet {
    s32 itemIds[3];
} Dll200ItemSet;

typedef struct Dll200WanderTarget {
    f32 x;
    f32 y;
    f32 moveId;
    f32 alternateMoveId;
    f32 animationStep;
} Dll200WanderTarget;

STATIC_ASSERT(sizeof(Dll200ItemSet) == 0x0C);
STATIC_ASSERT(sizeof(Dll200WanderTarget) == 0x14);

#define DLL200_ITEM_COUNT                 3
#define DLL200_HIT_REACT_ENTRY_COUNT      11
#define DLL200_WANDER_TARGET_COUNT        6
#define DLL200_MAP_ACT_INTERACT           1
#define DLL200_MAP_ACT_WANDER             2
#define DLL200_MAP_ACT_RENDER_GATED       4
#define DLL200_MAP_ACT_IDLE               6
#define DLL200_BEHAVIOR_MODE_TURN         12
#define DLL200_BEHAVIOR_MODE_PLAY_MOVE    13
#define DLL200_BEHAVIOR_MODE_HIT_REACTING 0x80
#define DLL200_OBJECT_TYPE_ID             1
#define DLL200_RENDER_SCALE               1.0f

const Dll200ItemSet gDll200WanderItemSet = {{0x166, 0x167, 0x256}};
const Dll200ItemSet gDll200IdleItemSet = {{0x166, 0x167, 0x256}};
ObjHitReactEntry gDll200HitReactTable[] = {
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
    {SFXpk_fuelcell_fizz, -1, -1, -1, 0, {0, 0, 0}, 0.0f, {0, 0, 0, 0}},
};
Dll200WanderTarget gDll200WanderTargets[] = {
    {0.0f, 0.0f, 0.0f, 0.0f, 0.02f},       {79.0f, 152.0f, 20.0f, 20.0f, 0.01f}, {138.0f, -6.0f, 20.0f, 20.0f, 0.02f},
    {-73.0f, -48.0f, 20.0f, 20.0f, 0.02f}, {-248.0f, -7.0f, 0.0f, 0.0f, 0.02f},  {0.0f, 0.0f, 0.0f, 0.0f, 0.02f},
};

STATIC_ASSERT(ARRAY_COUNT(gDll200HitReactTable) == DLL200_HIT_REACT_ENTRY_COUNT);
STATIC_ASSERT(ARRAY_COUNT(gDll200WanderTargets) == DLL200_WANDER_TARGET_COUNT);

/*
 * Retail data order places this exact descriptor before the TU's diagnostic
 * string and compiler-generated switch tables.
 */
ObjectDescriptor gDll200ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    dll_200_initialise,
    dll_200_release,
    0,
    (ObjectDescriptorCallback)dll_200_init,
    (ObjectDescriptorCallback)dll_200_update,
    dll_200_hitDetect,
    (ObjectDescriptorCallback)dll_200_render,
    dll_200_free,
    (ObjectDescriptorCallback)dll_200_getObjectTypeId,
    dll_200_getExtraSize,
};

char sDll200AngleDiffFormat[9] = "diff %d\n";

void dll_200_updateMapAct6(GameObject* obj) {
    Dll200State* state;
    Dll200ItemSet itemSet;

    state = obj->extra;
    Obj_GetPlayerObject();
    itemSet = gDll200IdleItemSet;
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_DISABLED) != 0) {
        obj->anim.resetHitboxFlags ^= INTERACT_FLAG_DISABLED;
    }
    if (mainGetBit(763) == 0) {
        if (obj->anim.currentMove != 7) {
            ObjAnim_SetCurrentMove(obj, 7, 0.0f, 0);
        }
        ObjAnim_AdvanceCurrentMove(obj, 0.005f, (f32)(u32)framesThisStep, NULL);
    } else {
        if (obj->anim.currentMove != 2) {
            ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
        }
        ObjAnim_AdvanceCurrentMove(obj, 0.005f, (f32)(u32)framesThisStep, NULL);
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0 && mainGetBit(763) == 0) {
        mainSetBits(763, 1);
        state->interactionCount = 0;
        buttonDisable(0, PAD_BUTTON_A);
    } else if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
        if ((*gGameUIInterface)->isOneOfItemsBeingUsed(itemSet.itemIds, DLL200_ITEM_COUNT) > -1) {
            mainSetBits(784, 1);
            state->interactionCount += 1;
            buttonDisable(0, PAD_BUTTON_A);
        }
    }
}

void dll_200_updateMapAct2(GameObject* obj) {
    Dll200State* state;
    u8 behaviorMode;
    s16 targetAngle;
    s16 angleDifference;
    f32 deltaX;
    f32 deltaY;
    f32 distance;
    f32 speed;
    Dll200ItemSet itemSet;
    ObjAnimEventList animEvents;

    state = obj->extra;
    Obj_GetPlayerObject();
    itemSet = gDll200WanderItemSet;
    obj->anim.localPosY = state->homeY;
    if (mainGetBit(GAMEBIT_WM_FoundKrystal) != 0) {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0 &&
            (*gGameUIInterface)->isOneOfItemsBeingUsed(itemSet.itemIds, DLL200_ITEM_COUNT) > -1) {
            mainSetBits(0x4d1, 1);
            state->interactionCount += 1;
            mainSetBits(0x310, 1);
            buttonDisable(0, PAD_BUTTON_A);
        }
    } else {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        if (state->behaviorTimer <= 0) {
            switch (randomGetRange(1, 4)) {
            case 1:
                state->previousBehaviorMode = state->behaviorMode;
                state->behaviorMode = 1;
                state->behaviorTimer = 400;
                break;
            case 2:
                state->previousBehaviorMode = state->behaviorMode;
                state->behaviorMode = 2;
                state->behaviorTimer = 400;
                break;
            case 3:
                state->previousBehaviorMode = state->behaviorMode;
                state->behaviorMode = 3;
                state->behaviorTimer = 400;
                break;
            case 4:
                state->previousBehaviorMode = state->behaviorMode;
                state->behaviorMode = 4;
                state->behaviorTimer = 400;
                break;
            case 5:
                state->previousBehaviorMode = state->behaviorMode;
                state->behaviorMode = 5;
                state->behaviorTimer = 400;
                break;
            }
        } else {
            behaviorMode = state->behaviorMode;
            if (behaviorMode == DLL200_BEHAVIOR_MODE_TURN) {
                targetAngle = getAngle(gDll200WanderTargets[state->previousBehaviorMode].x,
                                       gDll200WanderTargets[state->previousBehaviorMode].y);
                angleDifference = (s16)(targetAngle - obj->anim.rotX);
                logPrintf(sDll200AngleDiffFormat, angleDifference);
                if (angleDifference < -1000 || angleDifference > 1000) {
                    if (angleDifference > 0) {
                        obj->anim.rotX = (s16)(obj->anim.rotX + framesThisStep * 100);
                    } else {
                        obj->anim.rotX = (s16)(obj->anim.rotX - framesThisStep * 100);
                    }
                } else {
                    ObjAnim_SetCurrentMove(obj, gDll200WanderTargets[state->previousBehaviorMode].moveId, 0.0f, 0);
                    state->animationStep = gDll200WanderTargets[state->previousBehaviorMode].animationStep;
                    state->behaviorMode = DLL200_BEHAVIOR_MODE_PLAY_MOVE;
                }
            } else if (behaviorMode == DLL200_BEHAVIOR_MODE_PLAY_MOVE) {
                if (ObjAnim_AdvanceCurrentMove(obj, state->animationStep, timeDelta, &animEvents) != 0) {
                    if ((f32)(int)obj->anim.currentMove == gDll200WanderTargets[state->previousBehaviorMode].moveId) {
                        ObjAnim_SetCurrentMove(
                            obj, gDll200WanderTargets[state->previousBehaviorMode].alternateMoveId, 0.0f, 0);
                        state->animationStep = gDll200WanderTargets[state->previousBehaviorMode].animationStep;
                    }
                }
                state->behaviorTimer -= framesThisStep;
                if (state->behaviorTimer <= 0) {
                    state->behaviorTimer = 0;
                }
            } else {
                deltaX = gDll200WanderTargets[behaviorMode].x - (obj->anim.localPosX - state->homeX);
                deltaY = gDll200WanderTargets[behaviorMode].y - (obj->anim.localPosZ - state->homeZ);
                distance = sqrtf(deltaX * deltaX + deltaY * deltaY);
                targetAngle = getAngle(deltaX, deltaY);
                angleDifference = (s16)(targetAngle - obj->anim.rotX);
                if (angleDifference >= -1000 && angleDifference <= 1000) {
                    if (obj->anim.currentMove != 59) {
                        ObjAnim_SetCurrentMove(obj, 59, 0.0f, 0);
                        state->animationStep = 0.04f;
                    }
                    speed = 0.25f;
                    obj->anim.velocityX = speed * (deltaX / distance);
                    obj->anim.velocityZ = speed * (deltaY / distance);
                    ObjAnim_SampleRootCurvePhase(&obj->anim, speed, &state->animationStep);
                } else {
                    if (obj->anim.currentMove != 12) {
                        ObjAnim_SetCurrentMove(obj, 12, 0.0f, 0);
                        state->animationStep = 0.01f;
                    }
                    if (angleDifference > 0) {
                        obj->anim.rotX = (s16)(obj->anim.rotX + framesThisStep * 300);
                    } else {
                        obj->anim.rotX = (s16)(obj->anim.rotX - framesThisStep * 300);
                    }
                }
                if (distance < 4.0f) {
                    state->previousBehaviorMode = state->behaviorMode;
                    state->behaviorMode = DLL200_BEHAVIOR_MODE_TURN;
                    speed = 0.0f;
                    obj->anim.velocityX = speed;
                    obj->anim.velocityZ = speed;
                }
                obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
                obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
                ObjAnim_AdvanceCurrentMove(obj, state->animationStep, timeDelta, &animEvents);
            }
        }
    }
}

void dll_200_updateMapAct1(GameObject* obj) {
    Dll200State* state;

    state = obj->extra;
    if (obj->anim.currentMove != 2) {
        ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
    }
    ObjAnim_AdvanceCurrentMove(obj, 0.005f, (f32)(u32)framesThisStep, NULL);
    /* Retail writes and then immediately reloads this latch. */
    state->interactionLatch = 1;
    if (state->interactionLatch == 0) {
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            mainSetBits(GAMEBIT_WM_GalleonRelated00D0, 1);
            state->interactionLatch = 1;
            buttonDisable(0, PAD_BUTTON_A);
        }
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            GameObject* player = Obj_GetPlayerObject();
            if (playerGetCurMagic(player) > 0) {
                state->sequenceMode = 2;
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                buttonDisable(0, PAD_BUTTON_A);
            } else if (mainGetBit(177) == 0 || mainGetBit(178) == 0 || mainGetBit(179) == 0) {
                state->sequenceMode = 1;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                buttonDisable(0, PAD_BUTTON_A);
            }
        }
    }
}

int dll_200_processMapAct1Events(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate, int unusedArg4) {
    Dll200State* state;
    GameObject* player;
    int eventIndex;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;

    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        u8 sequenceMode = state->sequenceMode;
        if (sequenceMode == 1) {
            if (animUpdate->eventIds[eventIndex] == 4) {
                playerAddRemoveMagic(player, 5);
            }
        } else if (sequenceMode != 2) {
            u8 eventId = animUpdate->eventIds[eventIndex];
            if (eventId == 1) {
                mainSetBits(GAMEBIT_WM_GalleonRelated00D0, 1);
                state->interactionLatch = 1;
            } else if (eventId == 2) {
                playerSetHaveSpell(player, 0, 1);
                playerAddRemoveMagic(player, 5);
            }
        }
    }
    return 0;
}

int dll_200_sequenceCallback(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate, int unusedArg4) {
    u8 mapAct;
    int eventIndex;
    Dll200State* state;

    mapAct = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    switch (mapAct) {
    case 0:
        break;
    case DLL200_MAP_ACT_INTERACT:
        dll_200_processMapAct1Events(obj, unusedArg2, animUpdate, unusedArg4);
        break;
    case DLL200_MAP_ACT_WANDER:
        break;
    case DLL200_MAP_ACT_RENDER_GATED:
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        break;
    case DLL200_MAP_ACT_IDLE:
        state = obj->extra;
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
            switch (animUpdate->eventIds[eventIndex]) {
            case 0:
                break;
            case 1:
                if (state->interactionCount >= 2) {
                    mainSetBits(0x314, 1);
                }
                break;
            }
        }
        break;
    }
    return 0;
}

int dll_200_getExtraSize(void) {
    return sizeof(Dll200State);
}

int dll_200_getObjectTypeId(void) {
    return DLL200_OBJECT_TYPE_ID;
}

void dll_200_free(void) {
}

void dll_200_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    int mapAct;
    if (visible == 0) {
        return;
    }
    mapAct = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    if ((u8)mapAct == DLL200_MAP_ACT_RENDER_GATED) {
        if (mainGetBit(0x2bd) == 0u) {
            return;
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL200_RENDER_SCALE);
        return;
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL200_RENDER_SCALE);
}

void dll_200_hitDetect(void) {
}

void dll_200_update(GameObject* objectHandle) {
    u8 mapAct;
    u8 hitReactionActive;
    Dll200State* state;
    GameObject* obj = objectHandle;

    state = obj->extra;
    hitReactionActive = ObjHitReact_Update(obj, gDll200HitReactTable, DLL200_HIT_REACT_ENTRY_COUNT,
                                           (u8)((state->behaviorMode & DLL200_BEHAVIOR_MODE_HIT_REACTING) ? 1 : 0),
                                           &state->hitReactStepScale);
    if (hitReactionActive != 0) {
        state->behaviorMode = (u8)(state->behaviorMode | DLL200_BEHAVIOR_MODE_HIT_REACTING);
    } else {
        state->behaviorMode = (u8)(state->behaviorMode & ~DLL200_BEHAVIOR_MODE_HIT_REACTING);
        mapAct = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
        switch (mapAct) {
        case DLL200_MAP_ACT_INTERACT:
            dll_200_updateMapAct1(obj);
            break;
        case DLL200_MAP_ACT_WANDER:
            dll_200_updateMapAct2(obj);
            break;
        case DLL200_MAP_ACT_RENDER_GATED:
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
            if (obj->anim.currentMove != 2) {
                ObjAnim_SetCurrentMove(objectHandle, 2, 0.0f, 0);
            }
            ObjAnim_AdvanceCurrentMove(objectHandle, 0.005f, (f32)(u32)framesThisStep, NULL);
            break;
        case DLL200_MAP_ACT_IDLE:
            dll_200_updateMapAct6(obj);
            break;
        case 0:
        case 3:
        case 5:
            return;
        }
    }
}

void dll_200_init(GameObject* obj, const Dll200PlacementView* placement) {
    Dll200State* state;
    obj->userData1 = 0;
    obj->anim.rotX = (s16)((s32)placement->rotationXByte << 8);
    obj->animEventCallback = dll_200_sequenceCallback;
    state = obj->extra;
    state->objectIdLow = (u8)placement->base.objectId;
    state->unknown1C = 0;
    state->unknown18 = 0;
    state->homeX = placement->base.posX;
    state->homeY = placement->base.posY;
    state->homeZ = placement->base.posZ;
    state->interactionLatch = mainGetBit(GAMEBIT_WM_GalleonRelated00D0);
    state->interactionCount = 0;
    state->behaviorMode = 1;
    state->previousBehaviorMode = DLL200_BEHAVIOR_MODE_TURN;
    state->behaviorTimer = 0x12c;
    state->animationStep = 0.0f;
    state->unknown14 = 1.0f;
}

void dll_200_release(void) {
}

void dll_200_initialise(void) {
}
