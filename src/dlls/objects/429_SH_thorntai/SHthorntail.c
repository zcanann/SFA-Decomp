/*
 * SH_thorntail (DLL 0x1AD) - ThornTail Hollow herd-dinosaur behaviour.
 */
#include "dlls/objects/429_SH_thorntai.h"

#include "dolphin/os/OSReport.h"
#include "main/gamebits.h"
#include "main/vecmath.h"
#include "main/frustum.h"
#include "main/frame_timing.h"
#include "main/audio/sfx.h"
#include "dlls/object_descriptor.h"
#include "sys/objects.h"
#include "main/objtype.h"
#include "main/dll/dll_00C9_enemy.h"
#include "dolphin/os.h"
#include "game/objects/object.h"
#include "main/obj_trigger.h"
#include "main/mapEventTypes.h"
#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/model.h"
#include "main/objHitReact.h"
#include "main/objprint_character_api.h"
#include "main/object_render.h"
#include "main/obj_path.h"
#include "main/objseq.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/newshadows_audio_api.h"
#include "main/dll/path_control_interface.h"
#include "main/sky_interface.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"

extern u32 gSHthorntailDataTables[][4];
extern char sSHthorntailAngleYawDebug[];
#define SHTHORNTAIL_TIMER_DONE_THRESHOLD                  0.0f
#define SHTHORNTAIL_LINKED_EVENT_DISTANCE_SQ              40000.0f
#define SHTHORNTAIL_TAIL_SWING_WINDUP_TIME                180.0f
#define SHTHORNTAIL_TAIL_SWING_RECOVER_TIME               45.0f
#define SHTHORNTAIL_CLOSE_ATTACK_DISTANCE                 10000.0f
#define SHTHORNTAIL_LINKED_CONFIG_GROUP_COUNT             6
#define SHTHORNTAIL_LINKED_CONFIG_COUNT                   3
#define SHTHORNTAIL_HIT_REACT_ENTRY_COUNT                 25
#define SHTHORNTAIL_STATE_MOVE_ID_COUNT                   18
#define SHTHORNTAIL_STATE_STEP_SCALE_COUNT                17
#define SHTHORNTAIL_STATE_FLAG_BYTES                      0x14
#define SHTHORNTAIL_STATE_TRIGGER0_SFX_COUNT              18
#define SHTHORNTAIL_STATE_TRIGGER7_SFX_BYTES              0x14
#define SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES         0x0C
#define SHTHORNTAIL_PROXIMITY_ALERT_MIN_TIME              2.0f
#define SHTHORNTAIL_PROXIMITY_ALERT_MAX_TIME              5.0f
#define SHTHORNTAIL_IDLE_COUNTDOWN_TIME                   120.0f
#define SHTHORNTAIL_FLAG_MOVE_COMPLETE                    0x01
#define SHTHORNTAIL_FLAG_IMPACT_PENDING                   0x02
#define SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING            0x04
#define SHTHORNTAIL_FLAG_LEVELCONTROL_READY               0x08
#define SHTHORNTAIL_FLAG_FREEZE_MOTION                    0x10
#define SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME            0x08
#define SHTHORNTAIL_OBJECT_STATUS_ACTIVE                  0x10
#define SHTHORNTAIL_STATE_FLAG_STATUS_ACTIVE              0x01
#define SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT            0x02
#define SHTHORNTAIL_STATE_FLAG_DISABLE_MOVE_CONTROL       0x04
#define SHTHORNTAIL_STATE_FLAG_APPLY_ROOT_MOTION          0x08
#define SHTHORNTAIL_STATE_IDLE                            0x00
#define SHTHORNTAIL_STATE_IDLE_COUNTDOWN                  0x01
#define SHTHORNTAIL_STATE_MOVE_2                          0x02
#define SHTHORNTAIL_STATE_MOVE_3                          0x03
#define SHTHORNTAIL_STATE_MOVE_4                          0x04
#define SHTHORNTAIL_STATE_MOVE_5                          0x05
#define SHTHORNTAIL_STATE_TURN_HOME                       0x06
#define SHTHORNTAIL_STATE_CLOSE_ATTACK                    0x07
#define SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT               0x08
#define SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT             0x09
#define SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER            0x0A
#define SHTHORNTAIL_STATE_TAIL_SWING_READY                0x0B
#define SHTHORNTAIL_STATE_TAIL_SWING                      0x0C
#define SHTHORNTAIL_STATE_TAIL_SWING_RECOVER              0x0D
#define SHTHORNTAIL_STATE_EVENT_PAUSE                     0x0E
#define SHTHORNTAIL_STATE_ROOT_MODE2_EVENT                0x0F
#define SHTHORNTAIL_STATE_ROOT_MODE3_WAIT                 0x10
#define SHTHORNTAIL_TAIL_SWING_READY                      0x00
#define SHTHORNTAIL_TAIL_SWING_WINDUP                     0x01
#define SHTHORNTAIL_TAIL_SWING_ACTIVE                     0x02
#define SHTHORNTAIL_LOCOMOTION_1                          1
#define SHTHORNTAIL_LOCOMOTION_2                          2
#define SHTHORNTAIL_LOCOMOTION_3                          3
#define SHTHORNTAIL_LOCOMOTION_4                          4
#define SHTHORNTAIL_LOCOMOTION_5                          5
#define SHTHORNTAIL_LOCOMOTION_6                          6
#define SHTHORNTAIL_LOCOMOTION_7                          7
#define SHTHORNTAIL_LOCOMOTION_8                          8
#define SHTHORNTAIL_CONTROL_MODE_LEVEL_0                  0
#define SHTHORNTAIL_CONTROL_MODE_LEVEL_1                  1
#define SHTHORNTAIL_CONTROL_MODE_ROOT_2                   2
#define SHTHORNTAIL_CONTROL_MODE_ROOT_3                   3
#define SHTHORNTAIL_RENDER_PATH_POINT_COUNT               4
#define SHTHORNTAIL_CONFIG_TOKEN_NONE                     -1
#define SHTHORNTAIL_ALERT_VOLUME_ID                       0x410
#define SHTHORNTAIL_EVENT_RESUME_VOLUME_ID                0x409
#define SHTHORNTAIL_TAIL_SWING_WINDUP_VOLUME_ID           0xA9
#define SHTHORNTAIL_TAIL_SWING_ACTIVE_VOLUME_ID           0xA8
#define SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN                 500
#define SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX                 800
#define SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MIN               1
#define SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MAX               3
#define SHTHORNTAIL_IDLE_WAIT_MIN                         1000
#define SHTHORNTAIL_IDLE_WAIT_MAX                         2000
#define SHTHORNTAIL_INVALID_STATE_PANIC_LINE              0x6CD
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION2_GAMEBIT        0x0C2
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT        0x193
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_GATE_GAMEBIT   0x23C
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_EVENT_GAMEBIT  0x5BD
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT 0x23D
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT        0x13F
#define SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT        0x199
#define SHTHORNTAIL_ROOT_MODE3_TRIGGER_EVENT              0x1D
#define SHTHORNTAIL_ROOT_MODE3_TRIGGER_ARG                3
#define SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT   0x1A0
#define SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT         3
#define SHTHORNTAIL_PATH_CONTROL_MODE                     3
#define SHTHORNTAIL_PATH_CONTROL_FLAGS                    0xA3
#define SHTHORNTAIL_PATH_CHANNEL                          4

typedef struct SHthorntailLinkedConfigRow {
    s32 configToken;
    s32 linkedConfigTokens[SHTHORNTAIL_LINKED_CONFIG_COUNT];
} SHthorntailLinkedConfigRow;

typedef struct SHthorntailDataTables {
    SHthorntailLinkedConfigRow linkedConfigRows[SHTHORNTAIL_LINKED_CONFIG_GROUP_COUNT];
    u8 pathHeaders[0x30];
    u8 pathControlData[0x10];
    ObjHitReactEntry normalHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT];
    ObjHitReactEntry heavyHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT];
    s16 stateMoveIds[SHTHORNTAIL_STATE_MOVE_ID_COUNT];
    f32 stateMoveStepScales[SHTHORNTAIL_STATE_STEP_SCALE_COUNT];
    u8 stateFlags[SHTHORNTAIL_STATE_FLAG_BYTES];
    u16 stateTrigger0Sfx[SHTHORNTAIL_STATE_TRIGGER0_SFX_COUNT];
    u8 stateTrigger7Sfx[SHTHORNTAIL_STATE_TRIGGER7_SFX_BYTES];
    u8 levelMode0DefaultImpactSfxTable[0x10];
    u8 levelMode0Locomotion1ImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
    u8 levelMode0Locomotion2ClearImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
    u8 levelMode0Locomotion2SetImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
    u8 levelMode0Locomotion3ClearImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
    u8 levelMode0Locomotion3SetImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
    u8 levelMode0Locomotion5ClearImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
    u8 levelMode0Locomotion8ImpactSfxVariants[SHTHORNTAIL_LEVEL_MODE0_SFX_VARIANT_BYTES];
} SHthorntailDataTables;

typedef struct SHthorntailPathParams {
    u8 values[4];
} SHthorntailPathParams;

static const SHthorntailPathParams sSHthorntailPathParams = {{1, 1, 1, 1}};

s32 gSHthorntailActiveConfigToken = -1;
u8 gSHthorntailLevelControlMode1ImpactSfxTable[] = {1, 0x10};
u8 gSHthorntailRootControlMode2DefaultImpactSfxTable[] = {1, 0x14};
u8 gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable[] = {3, 0x2D, 0x2E, 0x2F};
u8 gSHthorntailRootControlMode3LocomotionDefaultImpactSfxTable[] = {4, 0x33, 0x34, 0x35, 0x36};
u8 gSHthorntailRootControlMode3Locomotion1ImpactSfxTable[] = {1, 0x37};
u8 gSHthorntailRootControlMode3Locomotion2ImpactSfxTable[] = {1, 0x38};
u8 gSHthorntailRootControlMode3Locomotion3ImpactSfxTable[] = {1, 0x39};
u8 gSHthorntailRootControlMode3Locomotion4ImpactSfxTable[] = {1, 0x3A};
u8 gSHthorntailRootControlMode3Locomotion5IdleImpactSfxTable[] = {1, 0x3B};
u8 gSHthorntailRootControlMode3Locomotion5PlayerImpactSfxTable[] = {1, 0x3C};
u8 gSHthorntailRootControlMode3Locomotion5EventImpactSfxTable[] = {1, 0x3D};
u8 gSHthorntailRootControlMode3Locomotion6ImpactSfxTable[] = {1, 0x3E};
u8 gSHthorntailRootControlMode3Locomotion7ImpactSfxTable[] = {1, 0x3F};
u8 gSHthorntailRootControlMode3Locomotion8ImpactSfxTable[] = {1, 0x40};

#define SHTHORNTAIL_OBJECT_TYPE_ID            0x4D7
#define SHTHORNTAIL_LINKED_EVENT_OBJECT_GROUP 3
#define SHTHORNTAIL_LINKED_CONFIG_ROW_BYTES   0x10
#define PLAYER_POS_OFFSET                     offsetof(GameObject, anim.worldPosX)
#define SHTHORNTAIL_PLACEMENT(obj)            ((SHthorntailPlacement*)(obj)->anim.placementData)

static inline s16 SHthorntail_getLinkedGameBit(const SHthorntailPlacement* placement) {
    return *(const s16*)&placement->controlMode;
}

int SHthorntail_HasNearbyPendingEventObject(GameObject* obj) {
    GameObject** objects;
    u32* linkedConfigRow;
    int count;
    int index;
    s8 groupIndex;
    int linkedEventPending;
    s8 matchCount;

    linkedEventPending = 0;
    groupIndex = -1;
    matchCount = 0;
    linkedConfigRow = gSHthorntailDataTables[0];
    for (index = 0; index < 6; index++) {
        if (SHTHORNTAIL_PLACEMENT(obj)->configToken == linkedConfigRow[0]) {
            groupIndex = index;
            break;
        }
        linkedConfigRow = (u32*)((u8*)linkedConfigRow + SHTHORNTAIL_LINKED_CONFIG_ROW_BYTES);
    }
    objects = (GameObject**)objGetAllOfType(SHTHORNTAIL_LINKED_EVENT_OBJECT_GROUP, &count);
    for (index = 0; index < count; index++) {
        if ((objects[index]->anim.romDefNo == SHTHORNTAIL_OBJECT_TYPE_ID) &&
            ((SHTHORNTAIL_PLACEMENT(objects[index])->configToken == gSHthorntailDataTables[groupIndex][1]) ||
             (SHTHORNTAIL_PLACEMENT(objects[index])->configToken == gSHthorntailDataTables[groupIndex][2]) ||
             (SHTHORNTAIL_PLACEMENT(objects[index])->configToken == gSHthorntailDataTables[groupIndex][3]))) {
            enemy_setTrackedObj(objects[index], obj);
            if ((vec3f_distanceSquared(&objects[index]->anim.worldPosX, &obj->anim.worldPosX) <
                 SHTHORNTAIL_LINKED_EVENT_DISTANCE_SQ) &&
                (mainGetBit(SHthorntail_getLinkedGameBit(SHTHORNTAIL_PLACEMENT(objects[index]))) == 0u)) {
                linkedEventPending = 1;
            }
            matchCount++;
            if (matchCount == SHTHORNTAIL_LINKED_CONFIG_COUNT) {
                break;
            }
        }
    }
    return linkedEventPending;
}

void SHthorntail_updateTailSwing(GameObject* objectId, SHthorntailState* state) {
    u8 tailSwingState;
    int moveComplete;

    tailSwingState = state->tailSwingState;
    switch (tailSwingState) {
    case SHTHORNTAIL_TAIL_SWING_READY:
        state->tailSwingTimer = state->tailSwingTimer - timeDelta;
        if (state->tailSwingTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD) {
            Sfx_PlayFromObject(objectId, SHTHORNTAIL_TAIL_SWING_WINDUP_VOLUME_ID);
            state->tailSwingState = SHTHORNTAIL_TAIL_SWING_WINDUP;
            state->tailSwingTimer = SHTHORNTAIL_TAIL_SWING_WINDUP_TIME;
        }
        break;
    case SHTHORNTAIL_TAIL_SWING_WINDUP:
        state->tailSwingTimer = state->tailSwingTimer - timeDelta;
        if (state->tailSwingTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD) {
            Sfx_PlayFromObject(objectId, SHTHORNTAIL_TAIL_SWING_ACTIVE_VOLUME_ID);
            state->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
        }
        break;
    case SHTHORNTAIL_TAIL_SWING_ACTIVE:
        moveComplete = state->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        if (moveComplete != 0) {
            state->tailSwingState = SHTHORNTAIL_TAIL_SWING_READY;
            state->tailSwingTimer = SHTHORNTAIL_TAIL_SWING_RECOVER_TIME;
        }
        break;
    default:
        break;
    }
}

u32 SHthorntail_chooseNextState(GameObject* object, SHthorntailState* state, SHthorntailPlacement* placement) {
    short angleDelta;
    int value;
    u32 nextState;
    s8 behaviorState;
    f32 dist;

    if (placement->leashRadius != '\0') {
        value = (int)Obj_GetPlayerObject();
        dist = getXZDistanceSquared(&object->anim.worldPosX, (f32*)(value + PLAYER_POS_OFFSET));
        if (dist < SHTHORNTAIL_CLOSE_ATTACK_DISTANCE) {
            behaviorState = state->behaviorState;
            if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) && (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
                nextState = SHTHORNTAIL_STATE_TURN_HOME;
            } else {
                nextState = SHTHORNTAIL_STATE_CLOSE_ATTACK;
            }
            return nextState;
        }
        dist = getXZDistanceSquared(&object->anim.worldPosX, (f32*)&placement->homePosition);
        if (dist > (float)(s32)(placement->leashRadius * placement->leashRadius)) {
            value = (s16)getAngle(object->anim.localPosX - placement->homePosition.x,
                                  object->anim.localPosZ - placement->homePosition.z);
            angleDelta = value - (u16)object->anim.rotX;
            if (angleDelta > 0x8000) {
                angleDelta = angleDelta - 0xFFFF;
            }
            if (angleDelta < -0x8000) {
                angleDelta = angleDelta + 0xFFFF;
            }
            value = angleDelta;
            value = (value >= 0) ? value : -value;
            if (value > 0x20) {
                OSReport(sSHthorntailAngleYawDebug,
                         (u16)getAngle(object->anim.localPosX - placement->homePosition.x,
                                       object->anim.localPosZ - placement->homePosition.z),
                         object->anim.rotX);
                behaviorState = state->behaviorState;
                if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) && (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
                    return SHTHORNTAIL_STATE_TURN_HOME;
                }
                return SHTHORNTAIL_STATE_CLOSE_ATTACK;
            }
        }
    } else {
        return SHTHORNTAIL_STATE_CLOSE_ATTACK;
    }
    value =
        ViewFrustum_IsSphereVisible(&object->anim.localPosX, object->anim.hitboxScale * object->anim.rootMotionScale);
    if (value == 0) {
        return SHTHORNTAIL_STATE_CLOSE_ATTACK;
    }
    behaviorState = state->behaviorState;
    if ((SHTHORNTAIL_STATE_MOVE_2 <= behaviorState) && (behaviorState <= SHTHORNTAIL_STATE_MOVE_5)) {
        nextState = randomGetRange(SHTHORNTAIL_STATE_MOVE_3, SHTHORNTAIL_STATE_MOVE_5);
        return nextState & 0xff;
    }
    return SHTHORNTAIL_STATE_MOVE_2;
}

u32 gSHthorntailDataTables[][4] = {
    {0x00044318, 0x0004467F, 0x00044677, 0x0004467B}, {0x000442FB, 0x00044641, 0x0004463F, 0x00044640},
    {0x00044309, 0x00044646, 0x00044648, 0x00044649}, {0x00044302, 0x0004432F, 0x0004431C, 0x0004432E},
    {0x000442F4, 0x0004463D, 0x0004463C, 0x0004463E}, {0x00044310, 0x00044636, 0x00044634, 0x00044637},
};

f32 gSHthorntailPathHeaders[12] = {-8.0f, 0.0f, -8.0f, 8.0f, 0.0f, -8.0f, 8.0f, 0.0f, 8.0f, -8.0f, 0.0f, 8.0f};

u8 gSHthorntailPathData[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02,
    0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F,
    0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7,
    0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23,
    0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C,
    0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00,
    0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2,
    0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02,
    0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F,
    0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x08, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7,
    0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23,
    0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C,
    0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00,
    0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF,
    0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00,
    0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2,
    0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02,
    0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F,
    0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23, 0xD7,
    0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x23,
    0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x3C,
    0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3F, 0x02, 0xC2, 0x00, 0x09, 0xFF, 0xFF, 0x00, 0x00, 0x00,
    0x00, 0x3C, 0x23, 0xD7, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x0D, 0x00, 0x0B,
    0x00, 0x0C, 0x00, 0x0F, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
    0x0A, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3C, 0x44, 0x9B, 0xA6,
    0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3C, 0x23, 0xD7, 0x0A, 0x3B, 0x83, 0x12,
    0x6F, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0x44, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0x23,
    0xD7, 0x0A, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3B, 0xC4, 0x9B, 0xA6, 0x3C, 0x23, 0xD7, 0x0A, 0x04,
    0x00, 0x08, 0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xB0, 0x02, 0xB0, 0x02,
    0xB0, 0x02, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xC2, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

u8 gSHthorntailLevelControlMode0DefaultImpactSfxTable[] = {
    0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x01, 0x0F,
    0x01, 0x10, 0x01, 0x11, 0x01, 0x12, 0x01, 0x13, 0x00, 0x00, 0x01, 0x16, 0x01, 0x18, 0x01, 0x1A, 0x01, 0x1C,
    0x01, 0x1E, 0x00, 0x00, 0x01, 0x17, 0x01, 0x19, 0x01, 0x1B, 0x01, 0x1D, 0x01, 0x1F, 0x00, 0x00, 0x01, 0x20,
    0x01, 0x22, 0x01, 0x24, 0x01, 0x26, 0x01, 0x28, 0x00, 0x00, 0x01, 0x21, 0x01, 0x23, 0x01, 0x25, 0x01, 0x27,
    0x01, 0x29, 0x00, 0x00, 0x01, 0x2B, 0x01, 0x2C, 0x01, 0x2C, 0x01, 0x2A, 0x01, 0x2B, 0x00, 0x00,
};

u8 gSHthorntailRootControlMode2Locomotion8ImpactSfxTable[] = {
    0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x01, 0x32, 0x01, 0x31, 0x00, 0x00,
};

ObjectDescriptor gSH_thorntailObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SHthorntail_init,
    (ObjectDescriptorCallback)SHthorntail_update,
    0,
    (ObjectDescriptorCallback)SHthorntail_render,
    (ObjectDescriptorCallback)SHthorntail_free,
    0,
    SHthorntail_getExtraSize,
};

char sSHthorntailAngleYawDebug[] = "angle %d, obj-yaw %d\n";
char sSHthorntailSourceFile[] = "SHthorntail.c";
char sThorntailEnteredInvalidState[] = "Thorntail entered an invalid state\n";

void SHthorntail_updateState(GameObject* obj, SHthorntailState* runtime) {
    int alertTriggered;
    int tailSwingQueued;
    int nextState;
    int randomValue;

    switch (runtime->behaviorState) {
    case SHTHORNTAIL_STATE_IDLE:
        alertTriggered = RandomTimer_UpdateRangeTrigger(
            &runtime->proximityAlertState, SHTHORNTAIL_PROXIMITY_ALERT_MIN_TIME, SHTHORNTAIL_PROXIMITY_ALERT_MAX_TIME);
        if (alertTriggered != 0) {
            Sfx_PlayFromObject(obj, SHTHORNTAIL_ALERT_VOLUME_ID);
        }
        runtime->idleTimer = runtime->idleTimer - timeDelta;
        if (runtime->idleTimer <= SHTHORNTAIL_IDLE_COUNTDOWN_TIME) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
        }
        break;
    case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
        runtime->idleTimer = runtime->idleTimer - timeDelta;
        if (runtime->idleTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD) {
            tailSwingQueued = (*gSkyInterface)->getSunPosition(0);
            if (tailSwingQueued != 0) {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
            } else {
                nextState = SHthorntail_chooseNextState(obj, runtime, (SHthorntailPlacement*)obj->anim.placementData);
                runtime->behaviorState = nextState;
            }
        }
        break;
    case SHTHORNTAIL_STATE_MOVE_2:
    case SHTHORNTAIL_STATE_MOVE_3:
    case SHTHORNTAIL_STATE_MOVE_4:
    case SHTHORNTAIL_STATE_MOVE_5:
    case SHTHORNTAIL_STATE_TURN_HOME:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            tailSwingQueued = (*gSkyInterface)->getSunPosition(0);
            if (tailSwingQueued != 0) {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
            } else {
                nextState = SHthorntail_chooseNextState(obj, runtime, (SHthorntailPlacement*)obj->anim.placementData);
                runtime->behaviorState = nextState;
            }
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
            randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN, SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX);
            runtime->comboTimer = (float)randomValue;
            randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MIN, SHTHORNTAIL_CLOSE_ATTACK_REPEAT_MAX);
            runtime->comboRepeatCount = randomValue;
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT:
        runtime->comboTimer = runtime->comboTimer - (float)framesThisStep;
        if (runtime->comboTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD) {
            if (runtime->comboRepeatCount <= 0) {
                runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER;
            } else {
                runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT;
            }
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK_REPEAT:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_CLOSE_ATTACK_WAIT;
            randomValue = randomGetRange(SHTHORNTAIL_CLOSE_ATTACK_WAIT_MIN, SHTHORNTAIL_CLOSE_ATTACK_WAIT_MAX);
            runtime->comboTimer = (float)randomValue;
            runtime->comboRepeatCount--;
        }
        break;
    case SHTHORNTAIL_STATE_CLOSE_ATTACK_RECOVER:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomValue;
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_READY:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
            runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING:
        SHthorntail_updateTailSwing(obj, runtime);
        if (((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) &&
            (tailSwingQueued = (*gSkyInterface)->getSunPosition(0), tailSwingQueued == 0)) {
            runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomValue;
        }
        break;
    default:
        OSPanic(sSHthorntailSourceFile, SHTHORNTAIL_INVALID_STATE_PANIC_LINE, sThorntailEnteredInvalidState);
    }
    return;
}

void SHthorntail_updateRootControlMode3(GameObject* obj, SHthorntailState* runtime) {
    int randomIdleWait;
    u32 gameBitValue;

    runtime->impactSfxTable = gSHthorntailRootControlMode3LocomotionDefaultImpactSfxTable;
    switch (runtime->locomotionMode) {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion1ImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION2_GAMEBIT);
        if (gameBitValue != 6) {
            runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion2ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
        if (gameBitValue == 0) {
            runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion3ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_4:
        runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion4ImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_GATE_GAMEBIT);
        if (gameBitValue == 0) {
            gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_EVENT_GAMEBIT);
            if (gameBitValue != 0) {
                (*gMapEventInterface)
                    ->setMapAct(SHTHORNTAIL_ROOT_MODE3_TRIGGER_EVENT, SHTHORNTAIL_ROOT_MODE3_TRIGGER_ARG);
                runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion5EventImpactSfxTable;
            } else {
                gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
                if (gameBitValue != 0) {
                    if (runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE3_WAIT) {
                        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
                        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
                        runtime->idleTimer = (float)randomIdleWait;
                    }
                    runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion5PlayerImpactSfxTable;
                } else {
                    runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion5IdleImpactSfxTable;
                    runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE3_WAIT;
                    return;
                }
            }
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_6:
        gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
        if (gameBitValue == 0) {
            runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion6ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_7:
        gameBitValue = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT);
        if (gameBitValue == 0) {
            runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion7ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable = gSHthorntailRootControlMode3Locomotion8ImpactSfxTable;
    }
    SHthorntail_updateState(obj, runtime);
}

void SHthorntail_updateRootControlMode2(GameObject* obj, SHthorntailState* runtime) {
    int linkedEventPending;
    int objectTriggerIsSet;
    u32 triggerIsSet;
    u32 triggerEventId;
    int randomTime;

    runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
    switch (runtime->locomotionMode) {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable = gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        runtime->impactSfxTable = gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        runtime->impactSfxTable = gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_4:
        runtime->impactSfxTable = gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        runtime->impactSfxTable = gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_6:
        linkedEventPending = SHthorntail_HasNearbyPendingEventObject(obj);
        if (linkedEventPending != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
            return;
        }
        if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
            Sfx_PlayFromObject(0, SHTHORNTAIL_EVENT_RESUME_VOLUME_ID);
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomTime;
        }
        runtime->impactSfxTable = gSHthorntailRootControlMode2DefaultImpactSfxTable;
        break;
    case SHTHORNTAIL_LOCOMOTION_7:
        if (runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE2_EVENT) {
            triggerEventId = mainGetBit(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
            triggerIsSet = mainGetBit(triggerEventId);
            if (triggerIsSet != 0) {
                (*gMapEventInterface)
                    ->setObjGroupStatus((int)obj->anim.mapEventSlot, SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT, 0);
                runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
                randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
                runtime->idleTimer = (float)randomTime;
            } else {
                return;
            }
        } else {
            triggerIsSet = mainGetBit(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
            if ((triggerIsSet == 0) && (objectTriggerIsSet = ObjTrigger_IsSet(obj), objectTriggerIsSet != 0)) {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE2_EVENT;
                (*gMapEventInterface)
                    ->setObjGroupStatus((int)obj->anim.mapEventSlot, SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT, 1);
                mainSetBits(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT, 1);
                return;
            }
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable = gSHthorntailRootControlMode2Locomotion8ImpactSfxTable + 6;
    }
    SHthorntail_updateState(obj, runtime);
}

typedef struct SHthorntailTailSwingEffectScratch {
    u8 particleParams[12];
    Vec position;
} SHthorntailTailSwingEffectScratch;

#define SHTHORNTAIL_PARTFX_TAILSWING 0x7f0 /* tail-swing effect (SHthorntailTailSwingEffectScratch) */

#define SHTHORNTAIL_LEVEL_MODE1_GATE_OPEN_GAMEBIT            0x13E
#define SHTHORNTAIL_LEVEL_MODE1_FREEZE_GAMEBIT               0x168
#define SHTHORNTAIL_LEVEL_MODE1_PRIMARY_TRIGGER_GAMEBIT      0xCD5
#define SHTHORNTAIL_LEVEL_MODE1_SECONDARY_TRIGGER_GAMEBIT    0xCD6
#define SHTHORNTAIL_LEVEL_MODE1_CLOSE_ATTACK_DISABLE_GAMEBIT 0x1AB
#define SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT          0x09E
#define SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL               0x7F
#define SHTHORNTAIL_LEVELCONTROL_COLLISION_FLAG              0x40

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET 0x0A0
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET  0x294
#define SHTHORNTAIL_STATE_MOVE_IDS_OFFSET           0x488
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET   0x4AC
#define SHTHORNTAIL_STATE_FLAGS_OFFSET              0x4F0
#define SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET       0x504
#define SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET       0x528

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(tables)                                                                   \
    ((ObjHitReactEntry*)((tables) + SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(tables)                                                                    \
    ((ObjHitReactEntry*)((tables) + SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_IDS(tables)         ((s16*)((tables) + SHTHORNTAIL_STATE_MOVE_IDS_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES(tables) ((f32*)((tables) + SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET))
#define SHTHORNTAIL_STATE_FLAGS(tables)            ((u8*)((tables) + SHTHORNTAIL_STATE_FLAGS_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER0_SFX(tables)     ((u16*)((tables) + SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER7_SFX(tables)     ((u8*)((tables) + SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET))

void SHthorntail_updateLevelControlMode1(GameObject* objectId, SHthorntailState* runtime, SHthorntailPlacement* placement) {
    GameObject* playerObj;
    int randomIdleWait;
    u8 closeToPlayer;
    u32 gameBit;
    int triggerIsSet;

    runtime->impactSfxTable = gSHthorntailLevelControlMode1ImpactSfxTable;
    playerObj = Obj_GetPlayerObject();
    {
        int cmp = getXZDistanceSquared(&objectId->anim.worldPosX, &playerObj->anim.worldPosX) <
                  SHTHORNTAIL_CLOSE_ATTACK_DISTANCE;
        closeToPlayer = cmp;
    }
    if (placement->impactSfxVariant == 0) {
        gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE1_GATE_OPEN_GAMEBIT);
        if (gameBit != 0) {
            gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE1_FREEZE_GAMEBIT);
            if (gameBit != 0) {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_FREEZE_MOTION;
                runtime->freezeFrameCounter = 0;
                closeToPlayer = FALSE;
            } else {
                triggerIsSet = ObjTrigger_IsSet(objectId);
                if (triggerIsSet != 0) {
                    runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                    mainSetBits(SHTHORNTAIL_LEVEL_MODE1_SECONDARY_TRIGGER_GAMEBIT, 1);
                }
            }
        } else {
            triggerIsSet = ObjTrigger_IsSet(objectId);
            if (triggerIsSet != 0) {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
                mainSetBits(SHTHORNTAIL_LEVEL_MODE1_PRIMARY_TRIGGER_GAMEBIT, 1);
            }
        }
    } else {
        gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE1_CLOSE_ATTACK_DISABLE_GAMEBIT);
        if (gameBit != 0) {
            closeToPlayer = FALSE;
        }
    }
    switch (runtime->behaviorState) {
    case SHTHORNTAIL_STATE_IDLE:
        if (!closeToPlayer) {
            runtime->idleTimer = SHTHORNTAIL_IDLE_COUNTDOWN_TIME;
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
        }
        break;
    case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
        if (closeToPlayer) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        } else {
            runtime->idleTimer = runtime->idleTimer - timeDelta;
            if (runtime->idleTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD) {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_READY;
            }
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_READY:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            if (closeToPlayer) {
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
            } else {
                runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
                runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
            }
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING:
        if (closeToPlayer) {
            runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING_RECOVER;
        } else {
            SHthorntail_updateTailSwing(objectId, runtime);
        }
        break;
    case SHTHORNTAIL_STATE_TAIL_SWING_RECOVER:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomIdleWait;
        }
        break;
    }
}

void SHthorntail_updateLevelControlMode0(GameObject* obj, SHthorntailState* runtime, SHthorntailPlacement* placement) {
    int linkedEventPending;
    u32 gameBit;
    int randomIdleWait;
    SHthorntailDataTables* dataTables;

    dataTables = (SHthorntailDataTables*)&gSHthorntailDataTables;
    runtime->impactSfxTable = dataTables->levelMode0DefaultImpactSfxTable;
    switch (runtime->locomotionMode) {
    case SHTHORNTAIL_LOCOMOTION_1:
        runtime->impactSfxTable =
            (u8*)dataTables->levelMode0Locomotion1ImpactSfxVariants + placement->impactSfxVariant * 2;
        break;
    case SHTHORNTAIL_LOCOMOTION_2:
        gameBit = mainGetBit(SHTHORNTAIL_LEVEL_MODE0_LOCOMOTION2_GAMEBIT);
        if (gameBit != 0) {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion2SetImpactSfxVariants + placement->impactSfxVariant * 2;
        } else {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion2ClearImpactSfxVariants + placement->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_3:
        gameBit = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION3_GAMEBIT);
        if (gameBit != 0) {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion3SetImpactSfxVariants + placement->impactSfxVariant * 2;
        } else {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion3ClearImpactSfxVariants + placement->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_5:
        gameBit = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION5_PLAYER_GAMEBIT);
        if (gameBit == 0) {
            runtime->impactSfxTable =
                (u8*)dataTables->levelMode0Locomotion5ClearImpactSfxVariants + placement->impactSfxVariant * 2;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_6:
        linkedEventPending = SHthorntail_HasNearbyPendingEventObject(obj);
        if (linkedEventPending != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
            return;
        }
        if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
            Sfx_PlayFromObject(0, SHTHORNTAIL_EVENT_RESUME_VOLUME_ID);
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (float)randomIdleWait;
        }
        gameBit = mainGetBit(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION6_GAMEBIT);
        if (gameBit == 0) {
            runtime->impactSfxTable = gSHthorntailLevelControlMode0Locomotion6ImpactSfxTable;
        }
        break;
    case SHTHORNTAIL_LOCOMOTION_8:
        runtime->impactSfxTable =
            (u8*)dataTables->levelMode0Locomotion8ImpactSfxVariants + placement->impactSfxVariant * 2;
        break;
    }
    SHthorntail_updateState(obj, runtime);
}

u32 SHthorntail_updateLevelControlState(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    SHthorntailState* runtime;
    int randomIdleWait;
    int impactHandled;
    int levelControlReady;
    int impactPending;

    runtime = obj->extra;
    levelControlReady = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_LEVELCONTROL_READY);
    if (levelControlReady == 0) {
        Sfx_StopObjectChannel(obj, SHTHORNTAIL_LEVELCONTROL_AUDIO_CHANNEL);
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (float)randomIdleWait;
        runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
        runtime->behaviorFlags =
            runtime->behaviorFlags | (SHTHORNTAIL_FLAG_LEVELCONTROL_READY | SHTHORNTAIL_FLAG_FREEZE_MOTION);
        runtime->freezeFrameCounter = 0;
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
    }
    impactPending = (int)(runtime->behaviorFlags & SHTHORNTAIL_FLAG_IMPACT_PENDING);
    if (impactPending != 0) {
        impactHandled = dll_2E_updateSequenceTurn(obj, animUpdate, (MoveLibState*)runtime, 0, 0);
        if (impactHandled != 0) {
            return 0;
        }
        animUpdate->flags &= ~SHTHORNTAIL_LEVELCONTROL_COLLISION_FLAG;
        characterDoEyeAnims(obj, &runtime->eyeAnimState);
    }
    runtime->activeMoveValid = 0;
    objAudioDispatchAnimEvents(obj, &animUpdate->animEvents, 8, runtime->renderPathPoints,
                               runtime->moveScratch, 1.0f, 1.0f);
    return 0;
}

int SHthorntail_getExtraSize(void) {
    return sizeof(SHthorntailState);
}

void SHthorntail_free(GameObject* obj) {
    SHthorntailPlacement* placement;
    u32 activeConfigToken;

    placement = (SHthorntailPlacement*)obj->anim.placementData;
    activeConfigToken = gSHthorntailActiveConfigToken;
    if (activeConfigToken == placement->configToken) {
        gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
    }
    objFreeObjectType(obj, SHTHORNTAIL_OBJECT_GROUP);
}

void SHthorntail_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    SHthorntailState* runtime;
    int pointIndex;

    runtime = obj->extra;
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    dll_2E_setTargetFromPathPoint(obj, (MoveLibState*)runtime, 0);
    pointIndex = 0;
    do {
        ObjPath_GetPointWorldPosition(obj, pointIndex, &runtime->renderPathPoints[0].x, &runtime->renderPathPoints[0].y,
                                      &runtime->renderPathPoints[0].z, 0);
        runtime = (SHthorntailState*)((u8*)runtime + sizeof(Vec));
        pointIndex = pointIndex + 1;
    } while (pointIndex < SHTHORNTAIL_RENDER_PATH_POINT_COUNT);
}

static void SHthorntail_applyGravity(GameObject* obj) {
    obj->anim.velocityY = -(0.17f * timeDelta - obj->anim.velocityY);
}

void SHthorntail_update(GameObject* obj) {
    u8* stateTables;
    SHthorntailState* runtime;
    SHthorntailPlacement* config;
    int i;
    s8* eventId;
    u8 hitResult;
    u8 mode;
    ObjHitReactEntry* hitReactEntries;
    int val;
    u32 uval;
    int ref;
    s32 activeConfigToken;
    f32 negSinFacing;
    f32 negCosFacing;
    f32 leashDistance;
    ObjAnimEventList animEvents;
    SHthorntailTailSwingEffectScratch effectScratch;

    stateTables = (u8*)&gSHthorntailDataTables;
    runtime = obj->extra;
    config = (SHthorntailPlacement*)(obj)->anim.placementData;
    if (runtime->behaviorState == '\f') {
        if (runtime->effectTimer <= SHTHORNTAIL_TIMER_DONE_THRESHOLD) {
            if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                ObjPath_GetPointWorldPosition(obj, 4, &effectScratch.position.x, &effectScratch.position.y,
                                              &effectScratch.position.z, 0);
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, SHTHORNTAIL_PARTFX_TAILSWING, effectScratch.particleParams, 0x200001, -1,
                                  NULL);
            }
            runtime->effectTimer = 30.0f;
        }
        runtime->effectTimer = runtime->effectTimer - timeDelta;
    }
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_LEVELCONTROL_READY;
    if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) != 0) {
        hitReactEntries = SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(stateTables);
    } else {
        hitReactEntries = SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(stateTables);
    }
    val = 0x19;
    hitResult = runtime->hitReactState =
        ObjHitReact_Update(obj, hitReactEntries, val, runtime->hitReactState, (float*)runtime->hitReactScratch);
    if (hitResult == 0) {
        mode = (*gMapEventInterface)->getMapAct((int)(obj)->anim.mapEventSlot);
        runtime->locomotionMode = mode;
        switch (config->controlMode) {
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
            SHthorntail_updateLevelControlMode0(obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
            SHthorntail_updateLevelControlMode1(obj, runtime, config);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
            SHthorntail_updateRootControlMode2(obj, runtime);
            break;
        case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
            SHthorntail_updateRootControlMode3(obj, runtime);
            break;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_STATUS_ACTIVE) !=
            0) {
            obj->anim.resetHitboxFlags |= SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
        } else {
            obj->anim.resetHitboxFlags &= ~SHTHORNTAIL_OBJECT_STATUS_ACTIVE;
            obj->anim.resetHitboxFlags &= ~SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
        }
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_FREEZE_MOTION) != 0) {
            if (++runtime->freezeFrameCounter > 0xa) {
                runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_FREEZE_MOTION;
            } else {
                obj->anim.resetHitboxFlags |= SHTHORNTAIL_OBJECT_STATUS_FREEZE_FRAME;
            }
        }
        if ((int)(obj)->anim.currentMove !=
            SHTHORNTAIL_STATE_MOVE_IDS(stateTables)[runtime->behaviorState]) {
            ObjAnim_SetCurrentMove(obj, SHTHORNTAIL_STATE_MOVE_IDS(stateTables)[runtime->behaviorState],
                                   SHTHORNTAIL_TIMER_DONE_THRESHOLD, 0);
            runtime->storedFacingAngle = obj->anim.rotX;
        }
        val = ObjAnim_AdvanceCurrentMove(obj, SHTHORNTAIL_STATE_MOVE_STEP_SCALES(stateTables)[runtime->behaviorState],
                                         timeDelta, &animEvents);
        if (val != 0) {
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        } else {
            runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_APPLY_ROOT_MOTION) !=
            0) {
            if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
                runtime->storedFacingAngle = obj->anim.rotX;
            }
            negSinFacing = -mathSinf((3.1415927f * (f32)(s32)runtime->storedFacingAngle) / 32768.0f);
            negCosFacing = -mathCosf((3.1415927f * (f32)(s32)runtime->storedFacingAngle) / 32768.0f);
            obj->anim.localPosX =
                negSinFacing * -animEvents.rootDeltaZ + obj->anim.localPosX;
            obj->anim.localPosZ =
                negCosFacing * -animEvents.rootDeltaZ + obj->anim.localPosZ;
            obj->anim.localPosX =
                negCosFacing * -animEvents.rootDeltaX + obj->anim.localPosX;
            obj->anim.localPosZ =
                negSinFacing * animEvents.rootDeltaX + obj->anim.localPosZ;
            obj->anim.rotX += animEvents.rootPitch;
        }
        for (i = 0, eventId = (s8*)&animEvents; i < animEvents.triggerCount; i = i + 1) {
            if (eventId[0x13] == '\0') {
                if (SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState] != 0) {
                    Sfx_PlayFromObject(obj,
                                       SHTHORNTAIL_STATE_TRIGGER0_SFX(stateTables)[runtime->behaviorState]);
                }
            } else if ((eventId[0x13] == '\a') &&
                       (SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState] != 0)) {
                Sfx_PlayFromObject((GameObject*)(u32)obj,
                                   SHTHORNTAIL_STATE_TRIGGER7_SFX(stateTables)[runtime->behaviorState]);
            }
            eventId++;
        }
        objAudioDispatchAnimEvents(obj, &animEvents, 8, runtime->renderPathPoints,
                                   runtime->moveScratch, 1.0f, 1.0f);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] &
             SHTHORNTAIL_STATE_FLAG_DISABLE_MOVE_CONTROL) != 0) {
            runtime->movementControlFlags = runtime->movementControlFlags & ~1;
        } else {
            runtime->movementControlFlags = runtime->movementControlFlags | 1;
        }
        dll_2E_updateLookAt(obj, (MoveLibState*)runtime);
        if ((SHTHORNTAIL_STATE_FLAGS(stateTables)[runtime->behaviorState] & SHTHORNTAIL_STATE_FLAG_HEAVY_HIT_REACT) !=
            0) {
            characterCloseEyes(obj, &runtime->eyeAnimState);
        } else {
            characterDoEyeAnims(obj, &runtime->eyeAnimState);
        }
        runtime->behaviorFlags = runtime->behaviorFlags & ~2;
        if (((runtime->behaviorFlags & 4) == 0) && (val = ObjTrigger_IsSet(obj), val != 0)) {
            uval = randomGetRange(1, (u32)*runtime->impactSfxTable);
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_IMPACT_PENDING;
            (*gObjectTriggerInterface)->runSequence(runtime->impactSfxTable[uval], (void*)obj, -1);
        }
        if (config->leashRadius != '\0') {
            leashDistance = getXZDistanceSquared(&obj->anim.worldPosX, (float*)&config->homePosition);
            if ((leashDistance > (f32)(s32)((u32)config->leashRadius * (u32)config->leashRadius)) &&
                (ref = ViewFrustum_IsSphereVisible(&obj->anim.localPosX, obj->anim.hitboxScale *
                                                                          obj->anim.rootMotionScale),
                 ref == 0)) {
                ref = getAngle(obj->anim.localPosX - config->homePosition.x,
                               obj->anim.localPosZ - config->homePosition.z);
                obj->anim.rotX = ref;
            }
        }
        runtime->activeMoveValid = 1;
        activeConfigToken = gSHthorntailActiveConfigToken;
        if (activeConfigToken == SHTHORNTAIL_CONFIG_TOKEN_NONE) {
            gSHthorntailActiveConfigToken =
                ((SHthorntailPlacement*)(obj)->anim.placementData)->configToken;
            obj->anim.velocityY = -(0.17f * timeDelta - obj->anim.velocityY);
            (*gPathControlInterface)->update((void*)obj, runtime->moveScratch, timeDelta);
            (*gPathControlInterface)->apply((void*)obj, runtime->moveScratch);
            (*gPathControlInterface)->advance((void*)obj, runtime->moveScratch, timeDelta);
            obj->anim.rotY = runtime->moveControlPitch;
            obj->anim.rotZ = runtime->moveControlRoll;
        } else {
            if ((u32)activeConfigToken ==
                (u32)((SHthorntailPlacement*)(obj)->anim.placementData)->configToken) {
                gSHthorntailActiveConfigToken = SHTHORNTAIL_CONFIG_TOKEN_NONE;
            }
            if (('\x02' <= runtime->behaviorState) && (runtime->behaviorState <= '\x06')) {
                obj->anim.velocityY = -(0.17f * timeDelta - obj->anim.velocityY);
                (*gPathControlInterface)->update((void*)obj, runtime->moveScratch, timeDelta);
                (*gPathControlInterface)->apply((void*)obj, runtime->moveScratch);
                (*gPathControlInterface)->advance((void*)obj, runtime->moveScratch, timeDelta);
                obj->anim.rotY = runtime->moveControlPitch;
                obj->anim.rotZ = runtime->moveControlRoll;
            } else {
                (*gPathControlInterface)->attachObject((void*)obj, runtime->moveScratch);
            }
        }
    }
    return;
}

void SHthorntail_init(GameObject* obj, const SHthorntailPlacement* placement) {
    SHthorntailState* runtime;
    ObjModel* model;
    u32 randomTime;
    u8* moveScratch;
    SHthorntailPathParams pathParam;

    runtime = obj->extra;
    pathParam = sSHthorntailPathParams;
    obj->anim.rotX = (short)((int)placement->initialFacing << 8);
    switch (placement->controlMode) {
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_0:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)randomTime;
        break;
    case SHTHORNTAIL_CONTROL_MODE_LEVEL_1:
        runtime->tailSwingState = SHTHORNTAIL_TAIL_SWING_ACTIVE;
        runtime->behaviorState = SHTHORNTAIL_STATE_TAIL_SWING;
        break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_2:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)randomTime;
        break;
    case SHTHORNTAIL_CONTROL_MODE_ROOT_3:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)(s32)randomTime;
        break;
    }
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase * ((float)placement->scale / 1000.0f);
    model = Obj_GetActiveModel(obj);
    modelInitBones(obj->anim.rootMotionScale, model);
    moveScratch = runtime->moveScratch;
    (*gPathControlInterface)->init(moveScratch, SHTHORNTAIL_PATH_CONTROL_MODE, SHTHORNTAIL_PATH_CONTROL_FLAGS, 0);
    (*gPathControlInterface)
        ->setup(moveScratch, SHTHORNTAIL_PATH_CHANNEL, gSHthorntailPathHeaders, gSHthorntailPathData, &pathParam);
    (*gPathControlInterface)->attachObject(obj, moveScratch);
    obj->animEventCallback = SHthorntail_updateLevelControlState;
    dll_2E_initState(obj, (MoveLibState*)runtime, 0xffffdc72, 0x2aaa, 3);
    dll_2E_setReattackDelay((MoveLibState*)runtime, 400, 0x78);
    objAddObjectType(obj, SHTHORNTAIL_OBJECT_GROUP);
}
