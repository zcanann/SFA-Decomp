#include "dlls/objects/328_CFGuardian.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_play_api.h"
#include "main/camera_interface.h"
#include "main/curve.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/player_api.h"
#include "main/dll/player_status.h"
#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/game_ui_interface.h"
#include "main/maketex_random_api.h"
#include "main/maketex_sequence_api.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_trigger.h"
#include "main/object_render.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objseq.h"
#include "main/pad_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "track/intersect_api.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/dll/savegame_object_api.h"

#define CFGUARDIAN_AIRBORNE_OBJECT_GROUP      0x16
#define CFGUARDIAN_TARGET_OBJECT_GROUP        3
#define CFGUARDIAN_SEQUENCE_TABLE_ENTRY_COUNT 15
#define CFGUARDIAN_MESSAGE_QUEUE_CAPACITY     4
#define CFGUARDIAN_OBJECT_TYPE_ID             0x41
#define CFGUARDIAN_MOVE_FLY                   0x1A
#define CFGUARDIAN_MOVE_LANDING               9
#define CFGUARDIAN_SEQUENCE_ID_MAGIC_GRANT    0x283
#define CFGUARDIAN_SEQUENCE_CHOICE_COUNT      3
#define CFGUARDIAN_SEQUENCE_TABLE_ROW_COUNT   33
#define CFGUARDIAN_IDLE_MOVE_COUNT            20
#define CFGUARDIAN_SFX_ID_COUNT               4
#define CFGUARDIAN_CHATTER_CHANCE_DENOMINATOR 60
#define CFGUARDIAN_CHATTER_PITCH              0x1000
#define CFGUARDIAN_MAGIC_THRESHOLD            3
#define CFGUARDIAN_MAGIC_GRANT_AMOUNT         10
#define CFGUARDIAN_WATER_SPELL_STONE_EVENT    0x2E8

#define GAMEBIT_CFGUARDIAN_PRISON_GUARD_STAND_DOWN 0x48
#define GAMEBIT_CFGUARDIAN_QUEST_STATE             0x4B
#define GAMEBIT_CFGUARDIAN_CAGE_OPEN               0x4E
#define GAMEBIT_CFGUARDIAN_PARKED                  0x4AA
#define GAMEBIT_CFGUARDIAN_TALK_2_COMPLETE         0x4BE
#define GAMEBIT_CFGUARDIAN_LANDED                  0x8E9

#define CFGUARDIAN_SFX_CHATTER 0xDF
#define CFGUARDIAN_SFX_FLAP    0xE1

typedef struct CfGuardianHitboxTemplate {
    s16 values[5];
} CfGuardianHitboxTemplate;

typedef struct CfGuardianSequenceMoves {
    int activeMoveA;
    int activeMoveB;
    int idleMoveA;
    int idleMoveB;
} CfGuardianSequenceMoves;

typedef struct CfGuardianUpdateScratch {
    f32 velocityDelta[3];
    u8 eventBuffer[0x1C];
} CfGuardianUpdateScratch;

typedef enum CfGuardianStateFlag {
    CFGUARDIAN_STATE_MOVE_LATCHED = 0x01,
    CFGUARDIAN_STATE_PATH_FLYING = 0x02,
    CFGUARDIAN_STATE_HOMING = 0x04,
} CfGuardianStateFlag;

typedef enum CfGuardianQuestState {
    CFGUARDIAN_STATE_DORMANT = 0,
    CFGUARDIAN_STATE_CAGED = 1,
    CFGUARDIAN_STATE_FLY_ESCAPE = 2,
    CFGUARDIAN_STATE_RELEASE_SEQUENCE = 3,
    CFGUARDIAN_STATE_ROOST = 4,
    CFGUARDIAN_STATE_LANDING = 6,
    CFGUARDIAN_STATE_FLY_TO_TALK = 7,
    CFGUARDIAN_STATE_TALK_1 = 8,
    CFGUARDIAN_STATE_TALK_2 = 9,
    CFGUARDIAN_STATE_FLY_OUT = 0x0A,
    CFGUARDIAN_STATE_VANISH = 0x0B,
    CFGUARDIAN_STATE_CUTSCENE_PERCH_A = 0x0C,
    CFGUARDIAN_STATE_CUTSCENE_PERCH_B = 0x0D,
    CFGUARDIAN_STATE_PARKED = 0x0E,
    CFGUARDIAN_STATE_PARKED_HIDDEN = 0x0F,
} CfGuardianQuestState;

typedef enum CfGuardianChatterState {
    CFGUARDIAN_CHATTER_READY = 1,
    CFGUARDIAN_CHATTER_PLAYING = 2,
} CfGuardianChatterState;

typedef enum CfGuardianAnimEvent {
    CFGUARDIAN_ANIM_EVENT_MOVE_SFX = 0,
    CFGUARDIAN_ANIM_EVENT_MARKER_1 = 1,
    CFGUARDIAN_ANIM_EVENT_MARKER_2 = 2,
    CFGUARDIAN_ANIM_EVENT_MARKER_3 = 3,
    CFGUARDIAN_ANIM_EVENT_MARKER_4 = 4,
    CFGUARDIAN_ANIM_EVENT_ALT_SFX = 7,
    CFGUARDIAN_ANIM_EVENT_FLAP_SFX = 9,
} CfGuardianAnimEvent;

STATIC_ASSERT(sizeof(CfGuardianHitboxTemplate) == 0x0A);
STATIC_ASSERT(sizeof(CfGuardianSequenceMoves) == 0x10);
STATIC_ASSERT(offsetof(CfGuardianUpdateScratch, eventBuffer) == 0x0C);
STATIC_ASSERT(sizeof(CfGuardianUpdateScratch) == 0x28);

s16 gCfGuardianSfxIds[CFGUARDIAN_SFX_ID_COUNT] = {0xDD, 0xDE, 0xE0, 0};

const CfGuardianHitboxTemplate gCfGuardianHitboxTemplateA = {{5, 15, 15, 0, 0}};
const CfGuardianHitboxTemplate gCfGuardianHitboxTemplateB = {{25, 25, 15, 5, 5}};
const CfGuardianSequenceMoves gCfGuardianSequenceMoves = {7, 8, 7, 8};

s32 gCfGuardianState0Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {1, 6, 13};
s32 gCfGuardianState1Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {15, 6, -1};
s32 gCfGuardianState2Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {5, -1, -1};
s32 gCfGuardianState3Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {2, -1, -1};
s32 gCfGuardianState4Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {8, 6, -1};
s32 gCfGuardianState5Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {12, -1, -1};
s32 gCfGuardianState6Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {14, -1, -1};
s32 gCfGuardianState7Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {14, 6, -1};
s32 gCfGuardianState8Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {14, 6, -1};
s32 gCfGuardianState9Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {9, 6, -1};
s32 gCfGuardianState10Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {5, -1, -1};
s32 gCfGuardianState12Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {11, -1, -1};
s32 gCfGuardianState13Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {10, -1, -1};
s32 gCfGuardianState14Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {14, 6, 16};
s32 gCfGuardianState15Sequences[CFGUARDIAN_SEQUENCE_CHOICE_COUNT] = {-1, -1, -1};

int gCfGuardianSeqStreamTable[CFGUARDIAN_SEQUENCE_TABLE_ROW_COUNT][2] = {
    {0, (int)&gCfGuardianState0Sequences},
    {1, (int)&gCfGuardianState1Sequences},
    {2, (int)&gCfGuardianState2Sequences},
    {3, (int)&gCfGuardianState3Sequences},
    {4, (int)&gCfGuardianState4Sequences},
    {5, (int)&gCfGuardianState5Sequences},
    {6, (int)&gCfGuardianState6Sequences},
    {7, (int)&gCfGuardianState7Sequences},
    {8, (int)&gCfGuardianState8Sequences},
    {9, (int)&gCfGuardianState9Sequences},
    {10, (int)&gCfGuardianState10Sequences},
    {12, (int)&gCfGuardianState12Sequences},
    {13, (int)&gCfGuardianState13Sequences},
    {14, (int)&gCfGuardianState14Sequences},
    {15, (int)&gCfGuardianState15Sequences},
    {0, 8},
    {1, 8},
    {2, 8},
    {3, 10},
    {4, 10},
    {5, 10},
    {6, 11},
    {7, 11},
    {8, 12},
    {9, 12},
    {10, -1},
    {12, -1},
    {13, -1},
    {14, -1},
    {15, -1},
    {0, 0},
    {0, 18},
    {14, 10},
};

int gCfGuardianIdleMoveTable[CFGUARDIAN_IDLE_MOVE_COUNT] = {
    -1, 0, 26, 0, 0, -1, -1, 26, 14, 14, 26, 26, 0, 0, -1, 10, 11, 12, 13, 14,
};

ObjectDescriptor11ExtraSize gCFGuardianObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    (ObjectDescriptorCallback)cfguardian_initialise,
    (ObjectDescriptorCallback)cfguardian_release,
    0,
    (ObjectDescriptorCallback)cfguardian_init,
    (ObjectDescriptorCallback)cfguardian_update,
    (ObjectDescriptorCallback)cfguardian_hitDetect,
    (ObjectDescriptorCallback)cfguardian_render,
    (ObjectDescriptorCallback)cfguardian_free,
    (ObjectDescriptorCallback)cfguardian_getObjectTypeId,
    cfguardian_getExtraSize,
    (ObjectDescriptorCallback)cfguardian_isNotPathFlying,
};

/* cfguardian_playEventSfx: walk this step's triggered anim events and play the
 * matching per-event sfx. sfxIds is a 3-entry table: [0] the move sfx,
 * [1] the alt (event 7) sfx, [2] the "selection" sfx played once if any
 * 1..4 marker event fired. Returns the last 1..4 marker seen. */
int cfguardian_playEventSfx(GameObject* obj, ObjAnimEventList* eventList, s16* sfxIds) {
    int eventIndex;
    u8 marker;

    marker = 0;
    for (eventIndex = 0; eventIndex < eventList->triggerCount; eventIndex++) {
        switch (eventList->triggeredIds[eventIndex]) {
        case CFGUARDIAN_ANIM_EVENT_MOVE_SFX:
            if (sfxIds != NULL) {
                Sfx_PlayFromObject(obj, sfxIds[0]);
            }
            break;
        case CFGUARDIAN_ANIM_EVENT_ALT_SFX:
            if (sfxIds != NULL) {
                Sfx_PlayFromObject(obj, sfxIds[1]);
            }
            break;
        case CFGUARDIAN_ANIM_EVENT_MARKER_1:
            marker = 1;
            break;
        case CFGUARDIAN_ANIM_EVENT_MARKER_2:
            marker = 2;
            break;
        case CFGUARDIAN_ANIM_EVENT_MARKER_3:
            marker = 3;
            break;
        case CFGUARDIAN_ANIM_EVENT_MARKER_4:
            marker = 4;
            break;
        case CFGUARDIAN_ANIM_EVENT_FLAP_SFX:
            Sfx_PlayFromObject(obj, CFGUARDIAN_SFX_FLAP);
            break;
        }
    }
    if (marker != 0 && sfxIds != NULL) {
        Sfx_PlayFromObject(obj, sfxIds[2]);
    }
    return marker;
}

/* cfguardian_isNotPathFlying: true when the guardian is not mid path-flight
 * (queried by the render path to decide whether to apply scale). */
int cfguardian_isNotPathFlying(GameObject* obj) {
    CfGuardianState* state = obj->extra;
    return (state->stateFlags & CFGUARDIAN_STATE_PATH_FLYING) == 0;
}

static f32 cfguardian_pathFraction(int pointIndex, int pointCount) {
    if (pointCount == 0) {
        return 0.0f;
    }
    return (f32)pointIndex / (f32)pointCount;
}

/* cfguardian_flyAlongPath: fly the guardian along a rom-curve path. On the first
 * tick (userData1 == 0) it steers to the nearest curve point then opens the
 * curve walker; thereafter it advances the walker, snaps the object to
 * the sampled position, sticks to the ground and blends the yaw toward
 * the heading of travel. Returns 1 once the path is exhausted. */
int cfguardian_flyAlongPath(GameObject* obj, RomCurveWalker* walker, f32 speed, int pointId, f32* outPhase) {
    int pathComplete;
    u8 curveGroup;
    int updateHeading;
    RomCurveDef* point;
    s16 yawDelta;
    int curveArgs[2];
    MoveLibTarget target;
    f32 groundDistance;

    updateHeading = 1;
    pathComplete = 0;
    groundDistance = 0.0f;
    if (obj->userData1 == -1) {
        return 1;
    }
    if (obj->userData1 == 0) {
        curveGroup = pointId;
        point = (RomCurveDef*)cfguardian_findRomCurvePointNearObject(obj, curveGroup, 0, 2);
        target.x = point->x;
        target.y = point->y;
        target.z = point->z;
        target.angle = point->yaw << 8;
        if (cfguardian_steerToward(obj, &target, speed, outPhase) != 0) {
            curveArgs[0] = 0x19;
            curveArgs[1] = 0x15;
            (*gRomCurveInterface)->initCurve(walker, obj, 200.0f, curveArgs, curveGroup);
            obj->userData1 = 1;
            updateHeading = 1;
        }
    } else {
        pathComplete = 0;
        if (Curve_AdvanceAlongPath(&walker->curve, speed) != 0 || walker->atSegmentEnd != 0) {
            pathComplete = (*gRomCurveInterface)->goNextPoint(walker);
        }
        obj->anim.localPosX = walker->posX;
        obj->anim.localPosY = walker->posY;
        obj->anim.localPosZ = walker->posZ;
        if (pathComplete != 0) {
            obj->userData1 = -1;
        }
        if (trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &groundDistance,
                                 0) == 0) {
            obj->anim.localPosY = obj->anim.localPosY - groundDistance;
        }
    }
    ObjAnim_SampleRootCurvePhase(&obj->anim, speed, outPhase);
    if (updateHeading != 0) {
        yawDelta = (s16)(getAngle(obj->anim.localPosX - obj->anim.previousLocalPosX,
                                  obj->anim.localPosZ - obj->anim.previousLocalPosZ) +
                         0x8000);
        yawDelta = yawDelta - (u16)obj->anim.rotX;
        if (yawDelta > 0x8000) {
            yawDelta = yawDelta - 0xffff;
        }
        if (yawDelta < -0x8000) {
            yawDelta = yawDelta + 0xffff;
        }
        obj->anim.rotX = obj->anim.rotX + (yawDelta >> 3);
    }
    if (obj->anim.currentMove != CFGUARDIAN_MOVE_FLY) {
        ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
    }
    return pathComplete;
}

/* cfguardian_steerToward: steer the object toward the target: scale its velocity
 * along the normalized delta, blend the yaw by speed over distance,
 * move it and keep the chase move playing. Returns 1 when already
 * within the closing threshold. */
int cfguardian_steerToward(GameObject* obj, MoveLibTarget* target, f32 speed, f32* outPhase) {
    f32 dist;
    f32 dx;
    f32 dy;
    f32 dz;
    s16 yawDelta;
    if (target == NULL) {
        return 0;
    }
    dx = target->x - obj->anim.localPosX;
    dy = target->y - obj->anim.localPosY;
    dz = target->z - obj->anim.localPosZ;
    {
        f32 sqDz = dz * dz;
        f32 sqDx = dx * dx;
        f32 sqDy = dy * dy;
        dist = sqrtf(sqDz + (sqDx + sqDy));
    }
    if (dist < 5.0f * speed) {
        return 1;
    }
    normalize(&dx, &dy, &dz);
    obj->anim.velocityX = timeDelta * (dx * speed);
    obj->anim.velocityY = timeDelta * (dy * speed);
    obj->anim.velocityZ = timeDelta * (dz * speed);
    yawDelta = (target->angle + 0x8000) - (u16)obj->anim.rotX;
    if (yawDelta > 0x8000) {
        yawDelta = yawDelta - 0xffff;
    }
    if (yawDelta < -0x8000) {
        yawDelta = yawDelta + 0xffff;
    }
    obj->anim.rotX = (f32)obj->anim.rotX + ((0.5f + yawDelta) * (speed * timeDelta)) / dist;
    objMove(obj, obj->anim.velocityX, obj->anim.velocityY, obj->anim.velocityZ);
    if (obj->anim.currentMove != CFGUARDIAN_MOVE_FLY) {
        ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
    }
    ObjAnim_SampleRootCurvePhase(&obj->anim, speed, outPhase);
    return 0;
}

RomCurveDef* cfguardian_findRomCurvePointNearObject(GameObject* obj, int curveGroup, f32* outPosition, int mode) {
    RomCurveDef* result = NULL;
    int curveTypes[2];
    int curveId;

    if (mode == 1) {
        curveTypes[0] = 0;
        curveTypes[1] = 0;
    } else {
        curveTypes[0] = 25;
        curveTypes[1] = 21;
    }

    curveId = (*gRomCurveInterface)
                  ->find(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, curveTypes, 2, curveGroup);

    if (curveId > -1) {
        result = (*gRomCurveInterface)->getById(curveId);
        if (outPosition != NULL) {
            outPosition[0] = result->x;
            outPosition[1] = result->y;
            outPosition[2] = result->z;
        }
    }
    return result;
}

/* cfguardian_updateMain: the Queen's brain - the fifteen-state quest
 * progression (path flights, landing physics, dialogue triggers and idle
 * chatter) that runs from her caged release through to the spell-stone
 * see-off. */

int cfguardian_updateMain(GameObject* obj) {
    CfGuardianState* state;
    GameObject* player;
    CfGuardianPlacement* placement;
    CfGuardianUpdateScratch scratch;
    f32 velocityScale;
    f32 nearestDistance = 1000.0f;
    f32 groundDistance = 1.0f;

    placement = (CfGuardianPlacement*)obj->anim.placement;
    scratch.eventBuffer[0x1b] = 0;
    state = obj->extra;
    state->stateFlags &= ~CFGUARDIAN_STATE_PATH_FLYING;
    state->moveSpeed = 0.005f;
    player = Obj_GetPlayerObject();
    ObjTrigger_UpdateIdBlockFlag(obj);
    if (placement->variant == 1 && mainGetBit(GAMEBIT_CF_PowerOn) == 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        return 0;
    }
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    /* quest state machine: 0..3 the release, 4/6/7 the flight home,
       8..11 the talk spots, 12..15 the endgame cutscene parks */
    switch (state->questState) {
    case CFGUARDIAN_STATE_DORMANT: /* dormant; wake once the quest starts (0x94f) */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        if (mainGetBit(GAMEBIT_CF_NotRecoveredStaff) != 0) {
            state->questState = CFGUARDIAN_STATE_CAGED;
        }
        break;
    case CFGUARDIAN_STATE_CAGED: /* wait for its own cage to open (0x4E - one of the four
               clouddungeon cage bits 0x4C-0x4F); alert + take off */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        if (mainGetBit(GAMEBIT_CFGUARDIAN_CAGE_OPEN) != 0) {
            state->questState = CFGUARDIAN_STATE_RELEASE_SEQUENCE;
            ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
            obj->userData1 = 0;
            mainSetBits(GAMEBIT_CFGUARDIAN_PRISON_GUARD_STAND_DOWN, 1);
            state->stateFlags |= CFGUARDIAN_STATE_MOVE_LATCHED;
        }
        break;
    case CFGUARDIAN_STATE_FLY_ESCAPE: /* fly the escape curve; roost at the end */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        state->stateFlags |= CFGUARDIAN_STATE_PATH_FLYING;
        if (cfguardian_flyAlongPath(obj, &state->path, 0.3f, 0, &state->moveSpeed) != 0) {
            state->stateFlags &= ~CFGUARDIAN_STATE_MOVE_LATCHED;
            state->questState = CFGUARDIAN_STATE_ROOST;
        }
        break;
    case CFGUARDIAN_STATE_RELEASE_SEQUENCE: /* play the release sequence once */
        (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        mainSetBits(GAMEBIT_ITEM_CFPowerKey_Got, 1);
        state->questState = CFGUARDIAN_STATE_FLY_ESCAPE;
        break;
    case CFGUARDIAN_STATE_ROOST: /* roost until the convergence cutscene parks her */
        if (mainGetBit(GAMEBIT_CF_PowerOn) != 0) {
            if (placement->variant != 1) {
                state->questState = CFGUARDIAN_STATE_PARKED_HIDDEN;
                state->chatterAlt = 0;
            } else {
                state->questState = CFGUARDIAN_STATE_PARKED;
                state->chatterAlt = 0;
            }
        } else if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
            state->chatterAlt = (state->chatterAlt + 1) % 2;
        }
        break;
    case CFGUARDIAN_STATE_LANDING: /* free-fall to the ground, then settle at the curve home */
        if (state->landingPhase != 0) {
            if (state->landingPhase >= 2) {
                {
                    f32 zero = 0.0f;
                    obj->anim.velocityX = zero;
                    obj->anim.velocityZ = zero;
                }
                obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
                trackGetNearestGroundOffset(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                     &groundDistance, 0);
                obj->anim.rotX = (s16)((0xc0 << (obj->anim.rotX + 8)) >> 1);
                ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_IMMOVABLE;
                if (groundDistance <= 1.0f) {
                    state->landingPhase = 2;
                    obj->anim.localPosY -= groundDistance;
                    state->chatterState = CFGUARDIAN_CHATTER_READY;
                    obj->userData1 = 0;
                    ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
                    {
                        RomCurveDef* homePoint =
                            (RomCurveDef*)cfguardian_findRomCurvePointNearObject(obj, 0, 0, 2);
                        f32 homeDistY;
                        state->home.x = homePoint->x;
                        state->home.y = homePoint->y;
                        state->home.z = homePoint->z;
                        state->home.angle = (s16)(homePoint->yaw << 8);
                        homeDistY = state->home.y - obj->anim.localPosY;
                        homeDistY = (homeDistY >= 0.0f) ? homeDistY : -homeDistY;
                        if (homeDistY < 80.0f) {
                            objAddObjectType(obj, CFGUARDIAN_AIRBORNE_OBJECT_GROUP);
                            state->questState = CFGUARDIAN_STATE_FLY_TO_TALK;
                            ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
                        }
                    }
                } else {
                    obj->anim.velocityY -= 0.12f;
                }
            } else {
                f32 rotationDelta;
                f32 rotation;
                rotationDelta = (400.0f * obj->anim.velocityY >= 0.0f) ? 400.0f * obj->anim.velocityY
                                                                       : -(400.0f * obj->anim.velocityY);
                rotation = (f32)obj->anim.rotX;
                rotation = rotation + rotationDelta;
                obj->anim.rotX = rotation;
                state->moveSpeed = 0.04f;
                if (mainGetBit(GAMEBIT_CFGUARDIAN_LANDED) != 0) {
                    ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
                    obj->anim.velocityY = 0.0f;
                    objFreeObjectType(obj, CFGUARDIAN_AIRBORNE_OBJECT_GROUP);
                    {
                        f32 zero = 0.0f;
                        obj->anim.velocityX = zero;
                        obj->anim.velocityY = -0.001f;
                        obj->anim.velocityZ = zero;
                    }
                    state->landingPhase = 2;
                    state->stateFlags &= ~CFGUARDIAN_STATE_MOVE_LATCHED;
                }
            }
            if (state->landingPhase < 2) {
                obj->anim.localPosX = timeDelta * obj->anim.velocityX + obj->anim.localPosX;
                obj->anim.localPosZ = timeDelta * obj->anim.velocityZ + obj->anim.localPosZ;
                if (state->bounceLatch != 0) {
                    {
                        f32 bounceScale = 0.8f;
                        obj->anim.velocityX = bounceScale * -obj->anim.velocityX;
                        obj->anim.velocityZ = bounceScale * -obj->anim.velocityZ;
                    }
                }
                {
                    f32 deltaY;
                    f32 deltaX;
                    f32 deltaZ;
                    f32 scaledDeltaZ;
                    deltaX = obj->anim.localPosX - obj->anim.previousLocalPosX;
                    scratch.velocityDelta[0] = deltaX;
                    deltaY = obj->anim.localPosY - obj->anim.previousLocalPosY;
                    scratch.velocityDelta[1] = deltaY;
                    deltaZ = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
                    scratch.velocityDelta[2] = deltaZ;
                    velocityScale = 0.95f * oneOverTimeDelta;
                    deltaX = deltaX * velocityScale;
                    scratch.velocityDelta[0] = deltaX;
                    deltaY = deltaY * velocityScale;
                    scratch.velocityDelta[1] = deltaY;
                    scaledDeltaZ = deltaZ * velocityScale;
                    scratch.velocityDelta[2] = scaledDeltaZ;
                    obj->anim.velocityX = deltaX + obj->anim.velocityX;
                    obj->anim.velocityY = deltaY + obj->anim.velocityY;
                    obj->anim.velocityZ = scaledDeltaZ + obj->anim.velocityZ;
                }
                {
                    f32 damping = 0.3f;
                    obj->anim.velocityX = damping * obj->anim.velocityX;
                    obj->anim.velocityY = damping * obj->anim.velocityY;
                    obj->anim.velocityZ = damping * obj->anim.velocityZ;
                }
            }
        } else if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        break;
    case CFGUARDIAN_STATE_FLY_TO_TALK: /* fly to the talk spot */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        state->stateFlags |= CFGUARDIAN_STATE_PATH_FLYING;
        if (cfguardian_flyAlongPath(obj, &state->path, 0.3f, 1, &state->moveSpeed) != 0) {
            state->questState = CFGUARDIAN_STATE_TALK_1;
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x32);
        }
        break;
    case CFGUARDIAN_STATE_TALK_1: /* talk spot: greet and head-track the player; 0x43 advances */
    {
        GameObject* nearestObject = objGetNearestTypeTo(CFGUARDIAN_TARGET_OBJECT_GROUP, obj, &nearestDistance);
        if (nearestObject != NULL && nearestDistance < 300.0f) {
            dll_2E_setLockTarget(&state->moveLib, nearestObject);
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
    }
        if (nearestDistance > 300.0f && Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < 80.0f) {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            if ((state->stateFlags & CFGUARDIAN_STATE_HOMING) == 0 &&
                gCfGuardianIdleMoveTable[state->questState] != 0) {
                dll_2E_getCurveActionTargetAimed(0xf, &state->home);
                state->stateFlags |= CFGUARDIAN_STATE_MOVE_LATCHED | CFGUARDIAN_STATE_HOMING;
                gCfGuardianIdleMoveTable[state->questState] = 0;
            }
            if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
                state->chatterState = CFGUARDIAN_CHATTER_READY;
                state->chatterAlt = (state->chatterAlt + 1) % 2;
            }
        } else if ((state->stateFlags & CFGUARDIAN_STATE_HOMING) == 0 &&
                   gCfGuardianIdleMoveTable[state->questState] != 0xe) {
            state->chatterState = CFGUARDIAN_CHATTER_PLAYING;
            state->stateFlags |= CFGUARDIAN_STATE_MOVE_LATCHED | CFGUARDIAN_STATE_HOMING;
            dll_2E_getCurveActionTarget(0xe, &state->home);
            gCfGuardianIdleMoveTable[state->questState] = 0xe;
        }
        if ((state->stateFlags & CFGUARDIAN_STATE_HOMING) != 0 &&
            cfguardian_steerToward(obj, &state->home, 0.5f, &state->moveSpeed) != 0) {
            ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
            state->stateFlags &= ~(CFGUARDIAN_STATE_MOVE_LATCHED | CFGUARDIAN_STATE_HOMING);
        }
        if (mainGetBit(GAMEBIT_CF_SavedQueen) != 0) {
            state->questState = CFGUARDIAN_STATE_TALK_2;
            state->chatterAlt = 0;
        }
        break;
    case CFGUARDIAN_STATE_TALK_2: /* second talk loop; 0x4be sends her onward */
    {
        GameObject* nearestObject = objGetNearestTypeTo(CFGUARDIAN_TARGET_OBJECT_GROUP, obj, &nearestDistance);
        if (nearestObject != NULL && nearestDistance < 300.0f) {
            dll_2E_setLockTarget(&state->moveLib, nearestObject);
        }
    }
        if (nearestDistance > 300.0f && Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < 80.0f) {
            if ((state->stateFlags & CFGUARDIAN_STATE_HOMING) == 0 &&
                gCfGuardianIdleMoveTable[state->questState] != 0) {
                dll_2E_getCurveActionTargetAimed(0xf, &state->home);
                state->stateFlags |= CFGUARDIAN_STATE_MOVE_LATCHED | CFGUARDIAN_STATE_HOMING;
                gCfGuardianIdleMoveTable[state->questState] = 0;
            }
            if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
                state->chatterState = CFGUARDIAN_CHATTER_READY;
                state->chatterAlt = (state->chatterAlt + 1) % 2;
            }
        } else if ((state->stateFlags & CFGUARDIAN_STATE_HOMING) == 0 &&
                   gCfGuardianIdleMoveTable[state->questState] != 0xe) {
            state->chatterState = CFGUARDIAN_CHATTER_PLAYING;
            state->stateFlags |= CFGUARDIAN_STATE_MOVE_LATCHED | CFGUARDIAN_STATE_HOMING;
            dll_2E_getCurveActionTarget(0xe, &state->home);
            gCfGuardianIdleMoveTable[state->questState] = 0xe;
        }
        if ((state->stateFlags & CFGUARDIAN_STATE_HOMING) != 0 &&
            cfguardian_steerToward(obj, &state->home, 0.5f, &state->moveSpeed) != 0) {
            ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
            state->stateFlags &= ~(CFGUARDIAN_STATE_MOVE_LATCHED | CFGUARDIAN_STATE_HOMING);
        }
        if (mainGetBit(GAMEBIT_CFGUARDIAN_TALK_2_COMPLETE) != 0) {
            state->questState = CFGUARDIAN_STATE_FLY_OUT;
            ObjAnim_SetCurrentMove(obj, CFGUARDIAN_MOVE_FLY, 0.0f, 0);
            obj->userData1 = 0;
        }
        break;
    case CFGUARDIAN_STATE_FLY_OUT: /* final flight out */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        state->stateFlags |= CFGUARDIAN_STATE_PATH_FLYING;
        if (cfguardian_flyAlongPath(obj, &state->path, 0.6f, 2, &state->moveSpeed) != 0) {
            state->questState = CFGUARDIAN_STATE_VANISH;
        }
        break;
    case CFGUARDIAN_STATE_VANISH: /* vanish: fade out and stop updating */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        obj->anim.alpha = 0;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        Obj_RemoveFromUpdateList(obj);
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        state->questState = CFGUARDIAN_STATE_PARKED_HIDDEN;
        break;
    case CFGUARDIAN_STATE_CUTSCENE_PERCH_A: /* cutscene perch: sequence 0xB on demand (0x4b7) */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        if (mainGetBit(GAMEBIT_TargetRelated04B7) != 0) {
            (*gCameraInterface)->setTarget(obj);
            (*gObjectTriggerInterface)->runSequence(0xb, (void*)obj, -1);
            mainSetBits(GAMEBIT_TargetRelated04B7, 0);
        }
        if (mainGetBit(GAMEBIT_SpellStoneRelated049A) != 0) {
            state->questState = CFGUARDIAN_STATE_CUTSCENE_PERCH_B;
        }
        break;
    case CFGUARDIAN_STATE_CUTSCENE_PERCH_B: /* cutscene perch: sequence 0xA on demand (0x4b7) */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        if (mainGetBit(GAMEBIT_TargetRelated04B7) != 0) {
            (*gCameraInterface)->setTarget(obj);
            (*gObjectTriggerInterface)->runSequence(0xa, (void*)obj, -1);
            mainSetBits(GAMEBIT_TargetRelated04B7, 0);
        }
        if (mainGetBit(GAMEBIT_CFGUARDIAN_PARKED) != 0) {
            state->questState = CFGUARDIAN_STATE_PARKED;
        }
        break;
    case CFGUARDIAN_STATE_PARKED: /* parked, idle chatter only */
        if (state->chatterState == CFGUARDIAN_CHATTER_PLAYING) {
            state->chatterState = CFGUARDIAN_CHATTER_READY;
        }
        break;
    case CFGUARDIAN_STATE_PARKED_HIDDEN: /* parked and hidden */
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        Obj_RemoveFromUpdateList(obj);
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        break;
    }
    dll_2E_updateLookAt(obj, &state->moveLib);
    if (ObjTrigger_IsSet(obj) != 0) {
        buttonDisable(0, PAD_BUTTON_A);
        if ((*gGameUIInterface)->isItemBeingUsed(CFGUARDIAN_WATER_SPELL_STONE_EVENT) != 0) {
            mainSetBits(GAMEBIT_WaterSpellStone1_4AB, 1);
        } else if (state->chatterState == CFGUARDIAN_CHATTER_READY) {
            int* sequenceChoices = (int*)seqPairTableLookup(gCfGuardianSeqStreamTable,
                                                            CFGUARDIAN_SEQUENCE_TABLE_ENTRY_COUNT, state->questState);
            int pick;
            if (playerGetCurMagic(player) > CFGUARDIAN_MAGIC_THRESHOLD) {
                pick = sequenceChoices[0];
            } else {
                pick = sequenceChoices[1];
            }
            if (state->chatterPick % 2 != 0 && sequenceChoices[2] != -1) {
                pick = sequenceChoices[2];
            }
            state->chatterPick += 1;
            if (pick != -1) {
                state->chatterState = CFGUARDIAN_CHATTER_PLAYING;
                (*gObjectTriggerInterface)->runSequence(pick, (void*)obj, -1);
            }
        }
    }
    if (mainGetBit(GAMEBIT_ITEM_WaterSpellStone1_902) != 0) {
        int* sequenceChoices = (int*)seqPairTableLookup(gCfGuardianSeqStreamTable,
                                                        CFGUARDIAN_SEQUENCE_TABLE_ENTRY_COUNT, state->questState);
        if (sequenceChoices[0] != -1) {
            state->chatterState = CFGUARDIAN_CHATTER_PLAYING;
            (*gObjectTriggerInterface)->runSequence(sequenceChoices[0], (void*)obj, -1);
            mainSetBits(GAMEBIT_ITEM_WaterSpellStone1_902, 0);
        }
    }
    {
        int idleMove = gCfGuardianIdleMoveTable[state->questState];
        if (idleMove != -1 && (state->stateFlags & CFGUARDIAN_STATE_MOVE_LATCHED) == 0 &&
            obj->anim.currentMove != idleMove) {
            ObjAnim_SetCurrentMove(obj, idleMove, 0.0f, 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x50);
        }
    }
    if (ObjAnim_AdvanceCurrentMove(obj, state->moveSpeed, framesThisStep,
                                   (ObjAnimEventList*)scratch.eventBuffer) != 0 &&
        (state->stateFlags & CFGUARDIAN_STATE_MOVE_LATCHED) != 0 && obj->anim.currentMove != CFGUARDIAN_MOVE_FLY &&
        obj->anim.currentMove != CFGUARDIAN_MOVE_LANDING) {
        state->stateFlags &= ~CFGUARDIAN_STATE_MOVE_LATCHED;
    }
    cfguardian_playEventSfx(obj, (ObjAnimEventList*)scratch.eventBuffer, gCfGuardianSfxIds);
    if (randomChanceOneIn(CFGUARDIAN_CHATTER_CHANCE_DENOMINATOR) != 0) {
        objSoundStartTimed(obj, &state->soundState, CFGUARDIAN_SFX_CHATTER, CFGUARDIAN_CHATTER_PITCH, -1, 0);
    }
    objSoundUpdateMouth(obj, &state->soundState);
    characterDoEyeAnims(obj, &state->eyeAnimState);
    if (state->questState != mainGetBit(GAMEBIT_CFGUARDIAN_QUEST_STATE)) {
        mainSetBits(GAMEBIT_CFGUARDIAN_QUEST_STATE, state->questState);
    }
    return 0;
}

/* cfguardian_sequenceCallback: the Queen's sequence message handler.
 * Persists position on a negative cue, otherwise picks the active/idle
 * heading pair and routes a move request; on the magic-grant cue
 * (curEventId 2) it refills the player's magic. Returns 1 if the move
 * was consumed. */
int cfguardian_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int* movePair;
    CfGuardianSequenceMoves sequenceMoves;
    CfGuardianState* state = obj->extra;

    sequenceMoves = gCfGuardianSequenceMoves;
    if (obj->seqIndex < 0) {
        saveGame_saveObjectPos(obj);
        return 0;
    }
    if (state->questState != CFGUARDIAN_STATE_LANDING) {
        movePair = &sequenceMoves.activeMoveA;
    } else {
        movePair = &sequenceMoves.idleMoveA;
    }
    if (animatedObjGetSeqId(animUpdate) != CFGUARDIAN_SEQUENCE_ID_MAGIC_GRANT) {
        if (dll_2E_updateSequenceTurn(obj, animUpdate, &state->moveLib, movePair[0], movePair[1]) != 0) {
            return 1;
        }
    }
    if (animUpdate->curEventId == 2) {
        playerAddRemoveMagic(Obj_GetPlayerObject(), CFGUARDIAN_MAGIC_GRANT_AMOUNT);
    }
    return 0;
}

int cfguardian_getExtraSize(void) {
    return sizeof(CfGuardianState);
}

int cfguardian_getObjectTypeId(void) {
    return CFGUARDIAN_OBJECT_TYPE_ID;
}

void cfguardian_free(GameObject* obj, int keep) {
    CfGuardianState* state = obj->extra;

    if (keep == 0) {
        int i;

        for (i = 0; i < CFGUARDIAN_LINKED_OBJECT_COUNT; i++) {
            GameObject* linkedObject = state->linkedObjects[i];

            if (linkedObject != NULL) {
                Obj_FreeObject(linkedObject);
            }
        }
    }
}

void cfguardian_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    CfGuardianState* state = obj->extra;

    if ((s32)visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        dll_2E_setTargetFromPathPoint(obj, &state->moveLib, 0);
    }
}

void cfguardian_hitDetect(GameObject* obj) {
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
}

void cfguardian_update(GameObject* obj) {
    cfguardian_updateMain(obj);
}

void cfguardian_init(GameObject* obj, CfGuardianPlacement* placement) {
    CfGuardianState* state;
    CfGuardianHitboxTemplate hitboxTemplateA;
    CfGuardianHitboxTemplate hitboxTemplateB;

    state = obj->extra;
    hitboxTemplateA = gCfGuardianHitboxTemplateA;
    hitboxTemplateB = gCfGuardianHitboxTemplateB;
    if (state == NULL) {
        return;
    }
    ObjMsg_AllocQueue(obj, CFGUARDIAN_MESSAGE_QUEUE_CAPACITY);
    state->questState = mainGetBit(GAMEBIT_CFGUARDIAN_QUEST_STATE);
    obj->userData1 = 1;
    obj->animEventCallback = cfguardian_sequenceCallback;
    obj->anim.rotX = (s16)(placement->initialYaw << 8);
    state->landingPhase = 0;
    state->moveSpeed = 0.0f;
    state->unknownA90 = 6;
    state->stateFlags = 0;
    state->flags611 = state->flags611 | 0x28;
    state->chatterState = CFGUARDIAN_CHATTER_READY;
    state->chatterAlt = 0;
    state->chatterPick = 0;
    if (mainGetBit(GAMEBIT_CF_PowerOn) != 0) {
        state->questState = CFGUARDIAN_STATE_ROOST;
        if (placement->variant == 0) {
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            Obj_RemoveFromUpdateList(obj);
        }
    } else if (mainGetBit(GAMEBIT_ITEM_CFPowerKey_Got) != 0 && placement->variant == 0) {
        state->questState = CFGUARDIAN_STATE_ROOST;
        dll_2E_getCurveActionTarget(8, (MoveLibTarget*)&obj->anim);
    }
    ObjHits_EnableObject(obj);
    dll_2E_initState(obj, &state->moveLib, -0x2000, 0x2800, 4);
    dll_2E_setReattackDelay(&state->moveLib, 0x12c, 0x64);
    dll_2E_setMoveTables(&state->moveLib, &hitboxTemplateB, &hitboxTemplateA, 4);
    seqPairTablePrepare(gCfGuardianSeqStreamTable, CFGUARDIAN_SEQUENCE_TABLE_ENTRY_COUNT);
    state->flags611 = state->flags611 | 0x2;
}

void cfguardian_release(void) {
}

void cfguardian_initialise(void) {
}
