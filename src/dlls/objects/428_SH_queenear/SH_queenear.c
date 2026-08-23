/*
 * SH_queenear (DLL 0x1AC) - the Queen EarthWalker in ThornTail
 * Hollow, the giant matriarch dinosaur the player tends.
 *
 * update() is driven by the area's map-event act: it picks the queen's
 * trigger-sequence event table for the current act, walks her toward the
 * player and runs idle/attention sequences. The feeding and open-portal
 * sub-handlers cover the berry-feeding interaction (Y-button item 0x66d)
 * and the spell-portal opening. stateIndex selects the locomotion move
 * and speed tables; the flags byte tracks the per-frame mode.
 */
#include "dlls/objects/428_SH_queenear.h"

#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/objprint_character_api.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/objprint_anim_api.h"
#include "main/obj_trigger.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"

#define QUEEN_EARTH_WALKER_TARGET_OBJECT_GROUP 0xF

#define QUEEN_EARTH_WALKER_REQUIRED_FEED_COUNT 6
#define QUEEN_EARTH_WALKER_LOOPING_SFX_CHANNEL 0x7F
#define QUEEN_EARTH_WALKER_PORTAL_SPELL_ID     3

/* QueenEarthWalkerState::flags bits */
#define QUEEN_EARTH_WALKER_FLAG_STARTED   0x01 /* First update ran; per-act logic engaged. */
#define QUEEN_EARTH_WALKER_FLAG_TARGETING 0x02 /* Targeting the player. */
#define QUEEN_EARTH_WALKER_FLAG_LATCHED   0x04 /* Player position captured. */
#define QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS 0x08 /* Run characterDoEyeAnims instead of the bite. */
#define QUEEN_EARTH_WALKER_FLAG_ACTIVE    0x10 /* Feeding completed; suppress idle attacks. */
#define QUEEN_EARTH_WALKER_FLAG_INIT_DONE 0x20 /* Per-frame animation-event handshake. */

typedef enum QueenEarthWalkerAnimEvent {
    QUEEN_EARTH_WALKER_ANIM_EVENT_ENABLE_EYE_ANIMS = 0,
    QUEEN_EARTH_WALKER_ANIM_EVENT_DISABLE_EYE_ANIMS = 1,
    QUEEN_EARTH_WALKER_ANIM_EVENT_BEGIN_TARGETING = 2,
    QUEEN_EARTH_WALKER_ANIM_EVENT_END_TARGETING = 3,
} QueenEarthWalkerAnimEvent;

const f32 gQueenEarthWalkerHeadLookBlend[1] = {0.0f};
const f32 gQueenEarthWalkerPortalSpellDistance[1] = {10000.0f};
const f32 gQueenEarthWalkerTrickyFeedDistance[1] = {22500.0f};
const f32 gQueenEarthWalkerAttackTimerMin[1] = {2.0f};
const f32 gQueenEarthWalkerAttackTimerMax[1] = {5.0f};

#define QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND          (gQueenEarthWalkerHeadLookBlend[0])
#define QUEEN_EARTH_WALKER_PORTAL_SPELL_DISTANCE_SQ (gQueenEarthWalkerPortalSpellDistance[0])
#define QUEEN_EARTH_WALKER_TRICKY_FEED_DISTANCE_SQ  (gQueenEarthWalkerTrickyFeedDistance[0])
#define QUEEN_EARTH_WALKER_ATTACK_TIMER_MIN         (gQueenEarthWalkerAttackTimerMin[0])
#define QUEEN_EARTH_WALKER_ATTACK_TIMER_MAX         (gQueenEarthWalkerAttackTimerMax[0])

u8 gQueenEarthWalkerEventTableAct1[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0, 0, 0};
u8 gQueenEarthWalkerEventTableAct2[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x14, 0, 0};
u8 gQueenEarthWalkerEventTableFed[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {2, 0x0C, 0x0A, 0};
u8 gQueenEarthWalkerEventTableFeed[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x0E, 0, 0};
u8 gQueenEarthWalkerEventTablePortalDefault[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x0F, 0, 0};
u8 gQueenEarthWalkerEventTablePortalReady[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x10, 0, 0};
u8 gQueenEarthWalkerEventTableSpell[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x11, 0, 0};
u8 gQueenEarthWalkerEventTableBerry[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x12, 0, 0};
u8 gQueenEarthWalkerEventTableDeparture[QUEEN_EARTH_WALKER_EVENT_TABLE_SIZE] = {1, 0x13, 0, 0};
u8 gQueenEarthWalkerEventTableComplete[QUEEN_EARTH_WALKER_COMPLETE_EVENT_TABLE_SIZE] = {5, 7, 8, 9, 0x0A, 0x0B, 0, 0};

s16 gQueenEarthWalkerMoveTable[QUEEN_EARTH_WALKER_MOVE_COUNT] = {34, 34, 34, 5, 28, 0};
f32 gQueenEarthWalkerMoveSpeedTable[QUEEN_EARTH_WALKER_MOVE_SPEED_COUNT] = {0.005f, 0.005f, 0.005f, 0.01f, 0.005f};

ObjectDescriptor gSH_queenearthwalkerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)sh_queenearthwalker_init,
    (ObjectDescriptorCallback)sh_queenearthwalker_update,
    0,
    0,
    0,
    0,
    sh_queenearthwalker_getExtraSize,
};

/*
 * Processes animation events that drive the Queen's attack and feeding
 * behaviour. Event IDs 0/1 enable and disable the eye-animation branch;
 * events 2/3 enter and leave targeting, with event 3 also arming two
 * hit-volume pair bits.
 *
 * While targeting, the Queen latches the player's position once and then
 * either runs the bite or eye tracking according to
 * QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS.
 * QUEEN_EARTH_WALKER_FLAG_INIT_DONE is a one-shot guard that stops the
 * looping object sound.
 */
int sh_queenearthwalker_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    QueenEarthWalkerState* state = obj->extra;
    int i;
    u8 flags;

    (void)unusedArg;

    if ((state->flags & QUEEN_EARTH_WALKER_FLAG_INIT_DONE) == 0) {
        Sfx_StopObjectChannel(obj, QUEEN_EARTH_WALKER_LOOPING_SFX_CHANNEL);
        state->flags &= ~QUEEN_EARTH_WALKER_FLAG_ACTIVE;
        state->flags |= QUEEN_EARTH_WALKER_FLAG_INIT_DONE;
    }

    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
        case QUEEN_EARTH_WALKER_ANIM_EVENT_ENABLE_EYE_ANIMS:
            state->flags |= QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS;
            break;
        case QUEEN_EARTH_WALKER_ANIM_EVENT_DISABLE_EYE_ANIMS:
            state->flags &= ~QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS;
            break;
        case QUEEN_EARTH_WALKER_ANIM_EVENT_BEGIN_TARGETING:
            state->flags |= QUEEN_EARTH_WALKER_FLAG_TARGETING;
            break;
        case QUEEN_EARTH_WALKER_ANIM_EVENT_END_TARGETING:
            state->flags &= ~QUEEN_EARTH_WALKER_FLAG_TARGETING;
            animUpdate->flags |= 0x8;
            animUpdate->flags |= 0x40;
            break;
        }
    }

    flags = state->flags;
    if ((flags & QUEEN_EARTH_WALKER_FLAG_TARGETING) != 0) {
        if ((flags & QUEEN_EARTH_WALKER_FLAG_LATCHED) == 0) {
            GameObject* player;

            animUpdate->flags &= ~0x8;
            player = Obj_GetPlayerObject();
            state->look.enabled = 1;
            state->look.targetX = player->anim.localPosX;
            state->look.targetY = player->anim.localPosY;
            state->look.targetZ = player->anim.localPosZ;
            characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
        }
        animUpdate->flags &= ~0x40;
        if ((state->flags & QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS) != 0) {
            characterCloseEyes(obj, &state->look);
        } else {
            characterDoEyeAnims(obj, &state->look);
        }
    }
    return 0;
}

void sh_queenearthwalker_updatePortal(GameObject* obj, QueenEarthWalkerState* state) {
    GameObject* player;

    player = Obj_GetPlayerObject();
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (mainGetBit(0xc48) != 0) {
        state->eventTable = gQueenEarthWalkerEventTableComplete;
    } else if (mainGetBit(GAMEBIT_SH_Related023C) != 0) {
        state->eventTable = gQueenEarthWalkerEventTablePortalReady;
    } else if (mainGetBit(GAMEBIT_STAFF_ABILITY_OPEN_PORTAL) != 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (playerHasSpell(player, QUEEN_EARTH_WALKER_PORTAL_SPELL_ID) != 0 &&
            getXZDistanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX) <
                QUEEN_EARTH_WALKER_PORTAL_SPELL_DISTANCE_SQ) {
            mainSetBits(0x23b, 1);
        }
    } else if (mainGetBit(GAMEBIT_SH_RescuedEggs) != 0) {
        state->eventTable = gQueenEarthWalkerEventTableComplete;
    } else {
        state->eventTable = gQueenEarthWalkerEventTablePortalDefault;
    }

    player = Obj_GetPlayerObject();
    state->look.enabled = 1;
    state->look.targetX = player->anim.localPosX;
    state->look.targetY = player->anim.localPosY;
    state->look.targetZ = player->anim.localPosZ;
    characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
}

void sh_queenearthwalker_updateFeeding(GameObject* obj, QueenEarthWalkerState* state) {
    s16 triggerId;
    s32 total;
    GameObject* tricky;
    GameObject* player;

    switch (state->stateIndex) {
    case 0:
        if (mainGetBit(GAMEBIT_SH_ReturnedToQueen) != 0) {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            state->stateIndex = 1;
        }
        break;
    case 1:
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (cMenuGetSelectedItem() == -1) {
            if (getYButtonItem(&triggerId) == 0 || triggerId != GAMEBIT_ITEM_WhiteShroom_Count) {
                tricky = getTrickyObject();
                if (tricky != NULL && getXZDistanceSquared(&tricky->anim.worldPosX, &obj->anim.worldPosX) <
                                          QUEEN_EARTH_WALKER_TRICKY_FEED_DISTANCE_SQ) {
                    Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
                } else {
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
                break;
            }
        }
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        if (ObjTrigger_IsSetById(obj, GAMEBIT_ITEM_WhiteShroom_Count) != 0) {
            state->flags |= QUEEN_EARTH_WALKER_FLAG_ACTIVE;
            total = mainGetBit(GAMEBIT_ITEM_WhiteShroom_Count);
            total += mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used);
            mainSetBits(GAMEBIT_ITEM_WhiteShroom_Count, 0);
            mainSetBits(GAMEBIT_ITEM_WhiteGrubTub_Used, total);
            if (total != QUEEN_EARTH_WALKER_REQUIRED_FEED_COUNT) {
                state->flags |= QUEEN_EARTH_WALKER_FLAG_TARGETING;
                if (randomGetRange(0, 1) != 0) {
                    (*gObjectTriggerInterface)->runSequence(3, obj, -1);
                } else {
                    (*gObjectTriggerInterface)->runSequence(4, obj, -1);
                }
            } else {
                (*gObjectTriggerInterface)->runSequence(5, obj, -1);
                state->stateIndex = 2;
            }
        }
        break;
    case 2:
        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
        mainSetBits(GAMEBIT_Tricky_Learned_Distract, 1);
        state->stateIndex = 3;
        break;
    case 3:
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        state->flags &= ~QUEEN_EARTH_WALKER_FLAG_LATCHED;
        state->flags &= ~QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS;
        state->eventTable = gQueenEarthWalkerEventTableFed;
        player = Obj_GetPlayerObject();
        state->look.enabled = 1;
        state->look.targetX = player->anim.localPosX;
        state->look.targetY = player->anim.localPosY;
        state->look.targetZ = player->anim.localPosZ;
        characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
        break;
    default:
        break;
    }
}

int sh_queenearthwalker_getExtraSize(void) {
    return sizeof(QueenEarthWalkerState);
}

void sh_queenearthwalker_update(GameObject* obj) {
    QueenEarthWalkerState* state;
    GameObject* player;
    GameObject* target;
    u8 action;
    s8 mapSlot;
    u8 stateFlags;
    u8 eventIndex;
    int currentMove;
    s16 targetMove;

    state = obj->extra;
    state->flags &= ~QUEEN_EARTH_WALKER_FLAG_INIT_DONE;
    mapSlot = obj->anim.mapEventSlot;
    action = (*gMapEventInterface)->getMapAct(mapSlot);

    if ((state->flags & QUEEN_EARTH_WALKER_FLAG_STARTED) != 0) {
        switch (action) {
        case 2:
            sh_queenearthwalker_updateFeeding(obj, state);
            break;
        case 3:
        case 4:
            if (mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got) != 0) {
                state->eventTable = gQueenEarthWalkerEventTableComplete;
            } else {
                state->eventTable = gQueenEarthWalkerEventTableFeed;
            }
            player = Obj_GetPlayerObject();
            state->look.enabled = 1;
            state->look.targetX = player->anim.localPosX;
            state->look.targetY = player->anim.localPosY;
            state->look.targetZ = player->anim.localPosZ;
            characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
            break;
        case 5:
            sh_queenearthwalker_updatePortal(obj, state);
            break;
        case 6:
            if (mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got) != 0) {
                state->eventTable = gQueenEarthWalkerEventTableComplete;
            } else {
                state->eventTable = gQueenEarthWalkerEventTableSpell;
            }
            player = Obj_GetPlayerObject();
            state->look.enabled = 1;
            state->look.targetX = player->anim.localPosX;
            state->look.targetY = player->anim.localPosY;
            state->look.targetZ = player->anim.localPosZ;
            characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
            break;
        case 7:
            if (mainGetBit(0x199) != 0) {
                state->eventTable = gQueenEarthWalkerEventTableComplete;
            } else {
                state->eventTable = gQueenEarthWalkerEventTableBerry;
            }
            player = Obj_GetPlayerObject();
            state->look.enabled = 1;
            state->look.targetX = player->anim.localPosX;
            state->look.targetY = player->anim.localPosY;
            state->look.targetZ = player->anim.localPosZ;
            characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
            break;
        case 8:
            player = Obj_GetPlayerObject();
            state->look.enabled = 1;
            state->look.targetX = player->anim.localPosX;
            state->look.targetY = player->anim.localPosY;
            state->look.targetZ = player->anim.localPosZ;
            characterHeadLookCalm(obj, (s16*)&state->look, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND);
            break;
        case 0:
        case 1:
        default:
            break;
        }
    } else {
        switch (action) {
        case 1:
            target = objGetNearestTypeTo(QUEEN_EARTH_WALKER_TARGET_OBJECT_GROUP, obj, NULL);
            (*gObjectTriggerInterface)->preempt((int)target, 0x1324);
            (*gObjectTriggerInterface)->runSequence(1, target, 0x10);
            state->flags |= (QUEEN_EARTH_WALKER_FLAG_LATCHED | QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS);
            state->eventTable = gQueenEarthWalkerEventTableAct1;
            break;
        case 2:
            if (mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used) == QUEEN_EARTH_WALKER_REQUIRED_FEED_COUNT) {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x18f6);
                (*gObjectTriggerInterface)->runSequence(6, obj, 1);
                state->stateIndex = 3;
            } else {
                if (mainGetBit(GAMEBIT_SH_ReturnedToQueen) != 0) {
                    state->stateIndex = 1;
                }
                state->flags |= (QUEEN_EARTH_WALKER_FLAG_LATCHED | QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS);
                state->eventTable = gQueenEarthWalkerEventTableAct2;
            }
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            (*gObjectTriggerInterface)->preempt((int)obj, 0x18f6);
            (*gObjectTriggerInterface)->runSequence(6, obj, 1);
            state->stateIndex = 3;
            break;
        case 8:
            target = objGetNearestTypeTo(QUEEN_EARTH_WALKER_TARGET_OBJECT_GROUP, obj, NULL);
            (*gObjectTriggerInterface)->preempt((int)target, 0x6a4);
            (*gObjectTriggerInterface)->runSequence(7, target, 8);
            state->stateIndex = 4;
            state->eventTable = gQueenEarthWalkerEventTableDeparture;
            break;
        default:
            break;
        }
        state->flags |= QUEEN_EARTH_WALKER_FLAG_STARTED;
        return;
    }

    if ((state->flags & QUEEN_EARTH_WALKER_FLAG_EYE_ANIMS) != 0) {
        characterCloseEyes(obj, &state->look);
    } else {
        characterDoEyeAnims(obj, &state->look);
    }

    currentMove = obj->anim.currentMove;
    targetMove = gQueenEarthWalkerMoveTable[state->stateIndex];
    if (currentMove != targetMove) {
        ObjAnim_SetCurrentMove(obj, targetMove, QUEEN_EARTH_WALKER_HEAD_LOOK_BLEND, 0);
    }
    ObjAnim_AdvanceCurrentMove(obj, gQueenEarthWalkerMoveSpeedTable[state->stateIndex], timeDelta, NULL);

    stateFlags = state->flags;
    if ((stateFlags & QUEEN_EARTH_WALKER_FLAG_ACTIVE) == 0) {
        state->flags &= ~QUEEN_EARTH_WALKER_FLAG_TARGETING;
        if (ObjTrigger_IsSet(obj) != 0 && obj->anim.hitVolumeBounds->flags != 4) {
            eventIndex = randomGetRange(1, *state->eventTable);
            state->flags |= QUEEN_EARTH_WALKER_FLAG_TARGETING;
            (*gObjectTriggerInterface)->runSequence(state->eventTable[eventIndex], obj, -1);
        }
    }

    if (RandomTimer_UpdateRangeTrigger(&state->attackTimer, QUEEN_EARTH_WALKER_ATTACK_TIMER_MIN,
                                       QUEEN_EARTH_WALKER_ATTACK_TIMER_MAX) != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_thorntail);
    }
}

void sh_queenearthwalker_init(GameObject* obj, QueenEarthWalkerPlacement* placement) {
    obj->anim.rotX = (s16)(placement->yawByte << 8);
    obj->animEventCallback = sh_queenearthwalker_processAnimEvents;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
}
