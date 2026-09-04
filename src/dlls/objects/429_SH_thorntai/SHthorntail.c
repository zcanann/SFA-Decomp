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

enum SHthorntailBehaviorState {
    SHTHORNTAIL_STATE_IDLE,
    SHTHORNTAIL_STATE_IDLE_COUNTDOWN,
    SHTHORNTAIL_STATE_WALK_START,
    SHTHORNTAIL_STATE_WALK_A,
    SHTHORNTAIL_STATE_WALK_B,
    SHTHORNTAIL_STATE_WALK_C,
    SHTHORNTAIL_STATE_WALK_STOP,
    SHTHORNTAIL_STATE_GRAZE_START,
    SHTHORNTAIL_STATE_GRAZE_WAIT,
    SHTHORNTAIL_STATE_GRAZE_REPEAT,
    SHTHORNTAIL_STATE_GRAZE_END,
    SHTHORNTAIL_STATE_FALLING_ASLEEP,
    SHTHORNTAIL_STATE_SLEEPING,
    SHTHORNTAIL_STATE_WAKING_UP,
    SHTHORNTAIL_STATE_EVENT_PAUSE,
    SHTHORNTAIL_STATE_TRIGGERED_EVENT,
    SHTHORNTAIL_STATE_EVENT_WAIT,
    SHTHORNTAIL_STATE_COUNT
};

enum SHthorntailVariant {
    SHTHORNTAIL_VARIANT_HERD,
    SHTHORNTAIL_VARIANT_SLEEPY,
    SHTHORNTAIL_VARIANT_TRIGGER,
    SHTHORNTAIL_VARIANT_STORY
};

enum SHthorntailSnoreState {
    SHTHORNTAIL_SNORE_DELAY,
    SHTHORNTAIL_SNORE_INHALE,
    SHTHORNTAIL_SNORE_EXHALE
};

#define SHTHORNTAIL_FLAG_MOVE_COMPLETE     0x01
#define SHTHORNTAIL_FLAG_TALK_SEQ_STARTED  0x02
#define SHTHORNTAIL_FLAG_TRIGGERED         0x04
#define SHTHORNTAIL_FLAG_IN_SEQUENCE       0x08
#define SHTHORNTAIL_FLAG_FREEZE_MOTION     0x10

#define SHTHORNTAIL_STATE_FLAG_HITBOX_ACTIVE 0x01
#define SHTHORNTAIL_STATE_FLAG_ASLEEP        0x02
#define SHTHORNTAIL_STATE_FLAG_NO_LOOK_AT    0x04
#define SHTHORNTAIL_STATE_FLAG_ROOT_MOTION   0x08

#define SHTHORNTAIL_HITBOX_FLAG_FREEZE_FRAME 0x08
#define SHTHORNTAIL_HITBOX_FLAG_ACTIVE       0x10

#define SHTHORNTAIL_LOOK_AT_ENABLED 0x01

#define SHTHORNTAIL_ANIM_EVENT_PRIMARY   0
#define SHTHORNTAIL_ANIM_EVENT_SECONDARY 7
#define SHTHORNTAIL_ANIM_AUDIO_TYPE      8

#define SHTHORNTAIL_SFX_ALERT         0x410
#define SHTHORNTAIL_SFX_EVENT_RESUME  0x409
#define SHTHORNTAIL_SFX_SNORE_INHALE  0xA9
#define SHTHORNTAIL_SFX_SNORE_EXHALE  0xA8
#define SHTHORNTAIL_SFX_STOP_CHANNEL  0x7F

#define SHTHORNTAIL_PARTFX_SLEEP       0x7F0
#define SHTHORNTAIL_PARTFX_SLEEP_FLAGS (PARTFXFLAG_200000 | PARTFXFLAG_1)
#define SHTHORNTAIL_SLEEP_EFFECT_POINT 4
#define SHTHORNTAIL_SLEEP_EFFECT_TIME  30.0f

#define SHTHORNTAIL_PLAYER_NEAR_DISTANCE_SQ 10000.0f
#define SHTHORNTAIL_LINKED_EVENT_DISTANCE_SQ 40000.0f
#define SHTHORNTAIL_SNORE_INHALE_TIME       180.0f
#define SHTHORNTAIL_SNORE_DELAY_TIME        45.0f
#define SHTHORNTAIL_PROXIMITY_ALERT_MIN_TIME 2.0f
#define SHTHORNTAIL_PROXIMITY_ALERT_MAX_TIME 5.0f
#define SHTHORNTAIL_IDLE_COUNTDOWN_TIME     120.0f
#define SHTHORNTAIL_GRAVITY                 0.17f
#define SHTHORNTAIL_HOME_YAW_TOLERANCE      0x20
#define SHTHORNTAIL_FREEZE_FRAME_COUNT      10

#define SHTHORNTAIL_GRAZE_WAIT_MIN   500
#define SHTHORNTAIL_GRAZE_WAIT_MAX   800
#define SHTHORNTAIL_GRAZE_REPEAT_MIN 1
#define SHTHORNTAIL_GRAZE_REPEAT_MAX 3
#define SHTHORNTAIL_IDLE_WAIT_MIN    1000
#define SHTHORNTAIL_IDLE_WAIT_MAX    2000

#define SHTHORNTAIL_LINKED_EVENT_OBJECT_GROUP 3
#define SHTHORNTAIL_LINKED_EVENT_OBJECT_ID    0x4D7
#define SHTHORNTAIL_LINKED_IDENT_ROWS         6
#define SHTHORNTAIL_LINKED_IDENT_COUNT        3
#define SHTHORNTAIL_HIT_REACT_ENTRY_COUNT     25
#define SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT    6
#define SHTHORNTAIL_PATH_POINT_COUNT          4
#define SHTHORNTAIL_PATH_CONTROL_MODE         3
#define SHTHORNTAIL_PATH_CONTROL_FLAGS        0xA3
#define SHTHORNTAIL_LOOK_AT_MIN_YAW           -0x238E
#define SHTHORNTAIL_LOOK_AT_MAX_YAW           0x2AAA
#define SHTHORNTAIL_LOOK_AT_POINT_COUNT       3
#define SHTHORNTAIL_REATTACK_DELAY_BASE       400
#define SHTHORNTAIL_REATTACK_DELAY_MIN        120
#define SHTHORNTAIL_PATH_OWNER_NONE           -1
#define SHTHORNTAIL_INVALID_STATE_LINE        1741

#define SHTHORNTAIL_STORY_ACT5_EVENT_MAP   0x1D
#define SHTHORNTAIL_STORY_ACT5_EVENT_ACT   3
#define SHTHORNTAIL_TRIGGER_ACT7_GAMEBIT   0x199
#define SHTHORNTAIL_TRIGGER_ACT7_GROUP_BIT 3

#define SHTHORNTAIL_PLACEMENT(obj)       ((SHthorntailPlacement*)(obj)->anim.placementData)
#define SHTHORNTAIL_EVENT_PLACEMENT(obj) ((SHthorntailEventPlacement*)(obj)->anim.placementData)

typedef struct SHthorntailEventPlacement {
    union {
        ObjPlacement base;
        struct {
            u8 pad00[0x14];
            s32 ident;
        };
    };
    s16 gameBit;
} SHthorntailEventPlacement;

typedef struct SHthorntailLinkedIdents {
    u32 ident;
    u32 linkedIdents[SHTHORNTAIL_LINKED_IDENT_COUNT];
} SHthorntailLinkedIdents;

typedef struct SHthorntailDataTables {
    SHthorntailLinkedIdents linkedIdents[SHTHORNTAIL_LINKED_IDENT_ROWS];
    Vec pathPoints[SHTHORNTAIL_PATH_POINT_COUNT];
    f32 pathRadii[SHTHORNTAIL_PATH_POINT_COUNT];
    ObjHitReactEntry hitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT];
    ObjHitReactEntry asleepHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT];
    s16 stateMoveIds[SHTHORNTAIL_STATE_COUNT];
    u8 pad4AA[0x2];
    f32 stateMoveStepScales[SHTHORNTAIL_STATE_COUNT];
    u8 stateFlags[SHTHORNTAIL_STATE_COUNT];
    u8 pad501[0x3];
    u16 statePrimaryEventSfx[SHTHORNTAIL_STATE_COUNT];
    u8 pad526[0x2];
    u8 stateSecondaryEventSfx[SHTHORNTAIL_STATE_COUNT];
    u8 pad539[0x3];
    u8 herdTalkSeqs[0x10];
    u8 herdAct1TalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
    u8 herdAct2ClearTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
    u8 herdAct2SetTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
    u8 herdAct3ClearTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
    u8 herdAct3SetTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
    u8 herdAct5ClearTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
    u8 herdAct8TalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2];
} SHthorntailDataTables;

STATIC_ASSERT(offsetof(SHthorntailDataTables, pathPoints) == 0x060);
STATIC_ASSERT(offsetof(SHthorntailDataTables, pathRadii) == 0x090);
STATIC_ASSERT(offsetof(SHthorntailDataTables, hitReactEntries) == 0x0A0);
STATIC_ASSERT(offsetof(SHthorntailDataTables, asleepHitReactEntries) == 0x294);
STATIC_ASSERT(offsetof(SHthorntailDataTables, stateMoveIds) == 0x488);
STATIC_ASSERT(offsetof(SHthorntailDataTables, stateMoveStepScales) == 0x4AC);
STATIC_ASSERT(offsetof(SHthorntailDataTables, stateFlags) == 0x4F0);
STATIC_ASSERT(offsetof(SHthorntailDataTables, statePrimaryEventSfx) == 0x504);
STATIC_ASSERT(offsetof(SHthorntailDataTables, stateSecondaryEventSfx) == 0x528);
STATIC_ASSERT(offsetof(SHthorntailDataTables, herdTalkSeqs) == 0x53C);
STATIC_ASSERT(offsetof(SHthorntailDataTables, herdAct1TalkSeqVariants) == 0x54C);
STATIC_ASSERT(offsetof(SHthorntailDataTables, herdAct8TalkSeqVariants) == 0x594);
STATIC_ASSERT(sizeof(SHthorntailDataTables) == 0x5A0);

#define SHTHORNTAIL_DATA_TABLES ((SHthorntailDataTables*)gSHthorntailLinkedIdents)

typedef struct SHthorntailPathSourceTypes {
    u8 values[SHTHORNTAIL_PATH_POINT_COUNT];
} SHthorntailPathSourceTypes;

static const SHthorntailPathSourceTypes sSHthorntailPathSourceTypes = {{1, 1, 1, 1}};

s32 gSHthorntailPathOwnerIdent = SHTHORNTAIL_PATH_OWNER_NONE;
u8 gSHthorntailSleepyTalkSeqs[] = {1, 0x10};
u8 gSHthorntailTriggerTalkSeqs[] = {1, 0x14};
u8 gSHthorntailHerdAct6TalkSeqs[] = {3, 0x2D, 0x2E, 0x2F};
u8 gSHthorntailStoryTalkSeqs[] = {4, 0x33, 0x34, 0x35, 0x36};
u8 gSHthorntailStoryAct1TalkSeqs[] = {1, 0x37};
u8 gSHthorntailStoryAct2TalkSeqs[] = {1, 0x38};
u8 gSHthorntailStoryAct3TalkSeqs[] = {1, 0x39};
u8 gSHthorntailStoryAct4TalkSeqs[] = {1, 0x3A};
u8 gSHthorntailStoryAct5IdleTalkSeqs[] = {1, 0x3B};
u8 gSHthorntailStoryAct5PlayerTalkSeqs[] = {1, 0x3C};
u8 gSHthorntailStoryAct5EventTalkSeqs[] = {1, 0x3D};
u8 gSHthorntailStoryAct6TalkSeqs[] = {1, 0x3E};
u8 gSHthorntailStoryAct7TalkSeqs[] = {1, 0x3F};
u8 gSHthorntailStoryAct8TalkSeqs[] = {1, 0x40};

SHthorntailLinkedIdents gSHthorntailLinkedIdents[SHTHORNTAIL_LINKED_IDENT_ROWS] = {
    {0x00044318, {0x0004467F, 0x00044677, 0x0004467B}}, {0x000442FB, {0x00044641, 0x0004463F, 0x00044640}},
    {0x00044309, {0x00044646, 0x00044648, 0x00044649}}, {0x00044302, {0x0004432F, 0x0004431C, 0x0004432E}},
    {0x000442F4, {0x0004463D, 0x0004463C, 0x0004463E}}, {0x00044310, {0x00044636, 0x00044634, 0x00044637}},
};

Vec gSHthorntailPathPoints[SHTHORNTAIL_PATH_POINT_COUNT] = {
    {-8.0f, 0.0f, -8.0f},
    {8.0f, 0.0f, -8.0f},
    {8.0f, 0.0f, 8.0f},
    {-8.0f, 0.0f, 8.0f},
};

f32 gSHthorntailPathRadii[SHTHORNTAIL_PATH_POINT_COUNT] = {0.0f, 0.0f, 0.0f, 0.0f};

#define SHTHORNTAIL_HIT_REACT_ENTRY(moveId) \
    { 0x23F, 0x2C2, moveId, -1, 0, {0, 0, 0}, 0.01f, {0, 0, 0, 0} }

ObjHitReactEntry gSHthorntailHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT] = {
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8), SHTHORNTAIL_HIT_REACT_ENTRY(8),
    SHTHORNTAIL_HIT_REACT_ENTRY(8),
};

ObjHitReactEntry gSHthorntailAsleepHitReactEntries[SHTHORNTAIL_HIT_REACT_ENTRY_COUNT] = {
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9), SHTHORNTAIL_HIT_REACT_ENTRY(9),
    SHTHORNTAIL_HIT_REACT_ENTRY(9),
};

s16 gSHthorntailStateMoveIds[SHTHORNTAIL_STATE_COUNT] = {
    0, 0, 14, 13, 11, 12, 15, 4, 5, 6, 7, 1, 2, 3, 10, 0, 16,
};

f32 gSHthorntailStateMoveStepScales[SHTHORNTAIL_STATE_COUNT] = {
    0.006f, 0.006f, 0.012f, 0.006f, 0.006f, 0.006f, 0.01f, 0.004f, 0.006f,
    0.003f, 0.006f, 0.006f, 0.0025f, 0.006f, 0.006f, 0.006f, 0.01f,
};

u8 gSHthorntailStateFlags[SHTHORNTAIL_STATE_COUNT] = {
    SHTHORNTAIL_STATE_FLAG_NO_LOOK_AT,
    0,
    SHTHORNTAIL_STATE_FLAG_ROOT_MOTION,
    SHTHORNTAIL_STATE_FLAG_ROOT_MOTION,
    SHTHORNTAIL_STATE_FLAG_ROOT_MOTION,
    SHTHORNTAIL_STATE_FLAG_ROOT_MOTION,
    SHTHORNTAIL_STATE_FLAG_ROOT_MOTION,
    0,
    0,
    0,
    0,
    SHTHORNTAIL_STATE_FLAG_HITBOX_ACTIVE,
    SHTHORNTAIL_STATE_FLAG_HITBOX_ACTIVE | SHTHORNTAIL_STATE_FLAG_ASLEEP,
    SHTHORNTAIL_STATE_FLAG_HITBOX_ACTIVE,
    SHTHORNTAIL_STATE_FLAG_HITBOX_ACTIVE,
    0,
    0,
};

u16 gSHthorntailStatePrimaryEventSfx[SHTHORNTAIL_STATE_COUNT] = {
    0, 0, 0, 0, 0, 0, 0, 0x2B0, 0x2B0, 0x2B0, 0x2B1, 0, 0, 0, 0, 0, 0x2C2,
};

u8 gSHthorntailStateSecondaryEventSfx[SHTHORNTAIL_STATE_COUNT] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

u8 gSHthorntailHerdTalkSeqs[] = {15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};

u8 gSHthorntailHerdAct1TalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x0F}, {1, 0x10}, {1, 0x11}, {1, 0x12}, {1, 0x13}, {0, 0},
};
u8 gSHthorntailHerdAct2ClearTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x16}, {1, 0x18}, {1, 0x1A}, {1, 0x1C}, {1, 0x1E}, {0, 0},
};
u8 gSHthorntailHerdAct2SetTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x17}, {1, 0x19}, {1, 0x1B}, {1, 0x1D}, {1, 0x1F}, {0, 0},
};
u8 gSHthorntailHerdAct3ClearTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x20}, {1, 0x22}, {1, 0x24}, {1, 0x26}, {1, 0x28}, {0, 0},
};
u8 gSHthorntailHerdAct3SetTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x21}, {1, 0x23}, {1, 0x25}, {1, 0x27}, {1, 0x29}, {0, 0},
};
u8 gSHthorntailHerdAct5ClearTalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x2B}, {1, 0x2C}, {1, 0x2C}, {1, 0x2A}, {1, 0x2B}, {0, 0},
};
u8 gSHthorntailHerdAct8TalkSeqVariants[SHTHORNTAIL_TALK_SEQ_VARIANT_COUNT][2] = {
    {1, 0x31}, {1, 0x30}, {1, 0x30}, {1, 0x32}, {1, 0x31}, {0, 0},
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

#define SHTHORNTAIL_STATE_ENTRY(type, table, state) (((type*)(table))[state])

static inline u8* SHthorntail_talkSeqVariant(u8* pairs, int variant) {
    return pairs + variant * 2;
}

int SHthorntail_HasNearbyPendingEventObject(GameObject* obj) {
    GameObject** objects;
    SHthorntailLinkedIdents* row;
    int count;
    int index;
    s8 rowIndex;
    int linkedEventPending;
    s8 matchCount;

    linkedEventPending = FALSE;
    rowIndex = -1;
    matchCount = 0;
    row = gSHthorntailLinkedIdents;
    for (index = 0; index < SHTHORNTAIL_LINKED_IDENT_ROWS; index++) {
        if (SHTHORNTAIL_PLACEMENT(obj)->ident == row->ident) {
            rowIndex = index;
            break;
        }
        row++;
    }
    objects = objGetAllOfType(SHTHORNTAIL_LINKED_EVENT_OBJECT_GROUP, &count);
    for (index = 0; index < count; index++) {
        if ((objects[index]->anim.romDefNo == SHTHORNTAIL_LINKED_EVENT_OBJECT_ID) &&
            ((SHTHORNTAIL_EVENT_PLACEMENT(objects[index])->ident ==
              gSHthorntailLinkedIdents[rowIndex].linkedIdents[0]) ||
             (SHTHORNTAIL_EVENT_PLACEMENT(objects[index])->ident ==
              gSHthorntailLinkedIdents[rowIndex].linkedIdents[1]) ||
             (SHTHORNTAIL_EVENT_PLACEMENT(objects[index])->ident ==
              gSHthorntailLinkedIdents[rowIndex].linkedIdents[2]))) {
            enemy_setTrackedObj(objects[index], obj);
            if ((vec3f_distanceSquared(&objects[index]->anim.worldPosX, &obj->anim.worldPosX) <
                 SHTHORNTAIL_LINKED_EVENT_DISTANCE_SQ) &&
                (mainGetBit(SHTHORNTAIL_EVENT_PLACEMENT(objects[index])->gameBit) == 0)) {
                linkedEventPending = TRUE;
            }
            matchCount++;
            if (matchCount == SHTHORNTAIL_LINKED_IDENT_COUNT) {
                break;
            }
        }
    }
    return linkedEventPending;
}

void SHthorntail_updateSnoring(GameObject* obj, SHthorntailState* runtime) {
    switch (runtime->snoreState) {
    case SHTHORNTAIL_SNORE_DELAY:
        runtime->snoreTimer = runtime->snoreTimer - timeDelta;
        if (runtime->snoreTimer <= 0.0f) {
            Sfx_PlayFromObject(obj, SHTHORNTAIL_SFX_SNORE_INHALE);
            runtime->snoreState = SHTHORNTAIL_SNORE_INHALE;
            runtime->snoreTimer = SHTHORNTAIL_SNORE_INHALE_TIME;
        }
        break;
    case SHTHORNTAIL_SNORE_INHALE:
        runtime->snoreTimer = runtime->snoreTimer - timeDelta;
        if (runtime->snoreTimer <= 0.0f) {
            Sfx_PlayFromObject(obj, SHTHORNTAIL_SFX_SNORE_EXHALE);
            runtime->snoreState = SHTHORNTAIL_SNORE_EXHALE;
        }
        break;
    case SHTHORNTAIL_SNORE_EXHALE:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->snoreState = SHTHORNTAIL_SNORE_DELAY;
            runtime->snoreTimer = SHTHORNTAIL_SNORE_DELAY_TIME;
        }
        break;
    default:
        break;
    }
}

u32 SHthorntail_chooseNextState(GameObject* obj, SHthorntailState* runtime, SHthorntailPlacement* placement) {
    GameObject* player;
    s16 yawDelta;
    int homeYaw;
    int yawDeltaAbs;
    int visible;
    u32 nextState;
    s8 behaviorState;
    f32 dist;

    if (placement->leashRadius != 0) {
        player = Obj_GetPlayerObject();
        dist = getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX);
        if (dist < SHTHORNTAIL_PLAYER_NEAR_DISTANCE_SQ) {
            behaviorState = runtime->behaviorState;
            if ((SHTHORNTAIL_STATE_WALK_START <= behaviorState) && (behaviorState <= SHTHORNTAIL_STATE_WALK_C)) {
                nextState = SHTHORNTAIL_STATE_WALK_STOP;
            } else {
                nextState = SHTHORNTAIL_STATE_GRAZE_START;
            }
            return nextState;
        }
        dist = getXZDistanceSquared(&obj->anim.worldPosX, &placement->homePosition.x);
        if (dist > (f32)(placement->leashRadius * placement->leashRadius)) {
            homeYaw = (s16)getAngle(obj->anim.localPosX - placement->homePosition.x,
                                    obj->anim.localPosZ - placement->homePosition.z);
            yawDelta = homeYaw - (u16)obj->anim.rotX;
            if (yawDelta > 0x8000) {
                yawDelta = yawDelta - 0xFFFF;
            }
            if (yawDelta < -0x8000) {
                yawDelta = yawDelta + 0xFFFF;
            }
            yawDeltaAbs = yawDelta;
            yawDeltaAbs = (yawDeltaAbs >= 0) ? yawDeltaAbs : -yawDeltaAbs;
            if (yawDeltaAbs > SHTHORNTAIL_HOME_YAW_TOLERANCE) {
                OSReport("angle %d, obj-yaw %d\n",
                         (u16)getAngle(obj->anim.localPosX - placement->homePosition.x,
                                       obj->anim.localPosZ - placement->homePosition.z),
                         obj->anim.rotX);
                behaviorState = runtime->behaviorState;
                if ((SHTHORNTAIL_STATE_WALK_START <= behaviorState) && (behaviorState <= SHTHORNTAIL_STATE_WALK_C)) {
                    return SHTHORNTAIL_STATE_WALK_STOP;
                }
                return SHTHORNTAIL_STATE_GRAZE_START;
            }
        }
    } else {
        return SHTHORNTAIL_STATE_GRAZE_START;
    }
    visible = ViewFrustum_IsSphereVisible(&obj->anim.localPosX, obj->anim.hitboxScale * obj->anim.rootMotionScale);
    if (visible == 0) {
        return SHTHORNTAIL_STATE_GRAZE_START;
    }
    behaviorState = runtime->behaviorState;
    if ((SHTHORNTAIL_STATE_WALK_START <= behaviorState) && (behaviorState <= SHTHORNTAIL_STATE_WALK_C)) {
        nextState = randomGetRange(SHTHORNTAIL_STATE_WALK_A, SHTHORNTAIL_STATE_WALK_C);
        return nextState & 0xff;
    }
    return SHTHORNTAIL_STATE_WALK_START;
}

void SHthorntail_updateState(GameObject* obj, SHthorntailState* runtime) {
    int alertTriggered;
    int isNight;
    int nextState;
    int randomValue;

    switch (runtime->behaviorState) {
    case SHTHORNTAIL_STATE_IDLE:
        alertTriggered = RandomTimer_UpdateRangeTrigger(
            &runtime->proximityAlertTimer, SHTHORNTAIL_PROXIMITY_ALERT_MIN_TIME, SHTHORNTAIL_PROXIMITY_ALERT_MAX_TIME);
        if (alertTriggered != 0) {
            Sfx_PlayFromObject(obj, SHTHORNTAIL_SFX_ALERT);
        }
        runtime->idleTimer = runtime->idleTimer - timeDelta;
        if (runtime->idleTimer <= SHTHORNTAIL_IDLE_COUNTDOWN_TIME) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
        }
        break;
    case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
        runtime->idleTimer = runtime->idleTimer - timeDelta;
        if (runtime->idleTimer <= 0.0f) {
            isNight = (*gSkyInterface)->getSunPosition(NULL);
            if (isNight != 0) {
                runtime->behaviorState = SHTHORNTAIL_STATE_FALLING_ASLEEP;
            } else {
                nextState = SHthorntail_chooseNextState(obj, runtime, SHTHORNTAIL_PLACEMENT(obj));
                runtime->behaviorState = nextState;
            }
        }
        break;
    case SHTHORNTAIL_STATE_WALK_START:
    case SHTHORNTAIL_STATE_WALK_A:
    case SHTHORNTAIL_STATE_WALK_B:
    case SHTHORNTAIL_STATE_WALK_C:
    case SHTHORNTAIL_STATE_WALK_STOP:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            isNight = (*gSkyInterface)->getSunPosition(NULL);
            if (isNight != 0) {
                runtime->behaviorState = SHTHORNTAIL_STATE_FALLING_ASLEEP;
            } else {
                nextState = SHthorntail_chooseNextState(obj, runtime, SHTHORNTAIL_PLACEMENT(obj));
                runtime->behaviorState = nextState;
            }
        }
        break;
    case SHTHORNTAIL_STATE_GRAZE_START:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_GRAZE_WAIT;
            randomValue = randomGetRange(SHTHORNTAIL_GRAZE_WAIT_MIN, SHTHORNTAIL_GRAZE_WAIT_MAX);
            runtime->grazeWaitTimer = (f32)randomValue;
            randomValue = randomGetRange(SHTHORNTAIL_GRAZE_REPEAT_MIN, SHTHORNTAIL_GRAZE_REPEAT_MAX);
            runtime->grazeRepeatCount = randomValue;
        }
        break;
    case SHTHORNTAIL_STATE_GRAZE_WAIT:
        runtime->grazeWaitTimer = runtime->grazeWaitTimer - (f32)framesThisStep;
        if (runtime->grazeWaitTimer <= 0.0f) {
            if (runtime->grazeRepeatCount <= 0) {
                runtime->behaviorState = SHTHORNTAIL_STATE_GRAZE_END;
            } else {
                runtime->behaviorState = SHTHORNTAIL_STATE_GRAZE_REPEAT;
            }
        }
        break;
    case SHTHORNTAIL_STATE_GRAZE_REPEAT:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_GRAZE_WAIT;
            randomValue = randomGetRange(SHTHORNTAIL_GRAZE_WAIT_MIN, SHTHORNTAIL_GRAZE_WAIT_MAX);
            runtime->grazeWaitTimer = (f32)randomValue;
            runtime->grazeRepeatCount--;
        }
        break;
    case SHTHORNTAIL_STATE_GRAZE_END:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (f32)randomValue;
        }
        break;
    case SHTHORNTAIL_STATE_FALLING_ASLEEP:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->snoreState = SHTHORNTAIL_SNORE_EXHALE;
            runtime->behaviorState = SHTHORNTAIL_STATE_SLEEPING;
        }
        break;
    case SHTHORNTAIL_STATE_SLEEPING:
        ((void (*)(GameObject*, SHthorntailState*))SHthorntail_updateSnoring)(obj, runtime);
        if (((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) &&
            (isNight = (*gSkyInterface)->getSunPosition(NULL), isNight == 0)) {
            runtime->behaviorState = SHTHORNTAIL_STATE_WAKING_UP;
        }
        break;
    case SHTHORNTAIL_STATE_WAKING_UP:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomValue = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (f32)randomValue;
        }
        break;
    default:
        OSPanic("SHthorntail.c", SHTHORNTAIL_INVALID_STATE_LINE, "Thorntail entered an invalid state\n");
    }
}

void SHthorntail_updateStoryVariant(GameObject* obj, SHthorntailState* runtime) {
    int randomIdleWait;
    u32 gameBitValue;

    runtime->talkSeqs = gSHthorntailStoryTalkSeqs;
    switch (runtime->mapAct) {
    case 1:
        runtime->talkSeqs = gSHthorntailStoryAct1TalkSeqs;
        break;
    case 2:
        gameBitValue = mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used);
        if (gameBitValue != 6) {
            runtime->talkSeqs = gSHthorntailStoryAct2TalkSeqs;
        }
        break;
    case 3:
        gameBitValue = mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got);
        if (gameBitValue == 0) {
            runtime->talkSeqs = gSHthorntailStoryAct3TalkSeqs;
        }
        break;
    case 4:
        runtime->talkSeqs = gSHthorntailStoryAct4TalkSeqs;
        break;
    case 5:
        gameBitValue = mainGetBit(GAMEBIT_SH_Related023C);
        if (gameBitValue == 0) {
            gameBitValue = mainGetBit(GAMEBIT_STAFF_ABILITY_OPEN_PORTAL);
            if (gameBitValue != 0) {
                (*gMapEventInterface)->setMapAct(SHTHORNTAIL_STORY_ACT5_EVENT_MAP, SHTHORNTAIL_STORY_ACT5_EVENT_ACT);
                runtime->talkSeqs = gSHthorntailStoryAct5EventTalkSeqs;
            } else {
                gameBitValue = mainGetBit(GAMEBIT_SH_ThornTailRelated023D);
                if (gameBitValue != 0) {
                    if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_WAIT) {
                        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
                        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
                        runtime->idleTimer = (f32)randomIdleWait;
                    }
                    runtime->talkSeqs = gSHthorntailStoryAct5PlayerTalkSeqs;
                } else {
                    runtime->talkSeqs = gSHthorntailStoryAct5IdleTalkSeqs;
                    runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_WAIT;
                    return;
                }
            }
        }
        break;
    case 6:
        gameBitValue = mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got);
        if (gameBitValue == 0) {
            runtime->talkSeqs = gSHthorntailStoryAct6TalkSeqs;
        }
        break;
    case 7:
        gameBitValue = mainGetBit(SHTHORNTAIL_TRIGGER_ACT7_GAMEBIT);
        if (gameBitValue == 0) {
            runtime->talkSeqs = gSHthorntailStoryAct7TalkSeqs;
        }
        break;
    case 8:
        runtime->talkSeqs = gSHthorntailStoryAct8TalkSeqs;
    }
    SHthorntail_updateState(obj, runtime);
}

void SHthorntail_updateTriggerVariant(GameObject* obj, SHthorntailState* runtime) {
    int linkedEventPending;
    int objectTriggerIsSet;
    u32 triggerIsSet;
    u32 triggerGameBit;
    int randomTime;

    runtime->talkSeqs = gSHthorntailHerdTalkSeqs;
    switch (runtime->mapAct) {
    case 1:
        runtime->talkSeqs = gSHthorntailTriggerTalkSeqs;
        break;
    case 2:
        runtime->talkSeqs = gSHthorntailTriggerTalkSeqs;
        break;
    case 3:
        runtime->talkSeqs = gSHthorntailTriggerTalkSeqs;
        break;
    case 4:
        runtime->talkSeqs = gSHthorntailTriggerTalkSeqs;
        break;
    case 5:
        runtime->talkSeqs = gSHthorntailTriggerTalkSeqs;
        break;
    case 6:
        linkedEventPending = ((int (*)(GameObject*))SHthorntail_HasNearbyPendingEventObject)(obj);
        if (linkedEventPending != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
            return;
        }
        if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
            Sfx_PlayFromObject(NULL, SHTHORNTAIL_SFX_EVENT_RESUME);
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (f32)randomTime;
        }
        runtime->talkSeqs = gSHthorntailTriggerTalkSeqs;
        break;
    case 7:
        if (runtime->behaviorState == SHTHORNTAIL_STATE_TRIGGERED_EVENT) {
            triggerGameBit = mainGetBit(GAMEBIT_SH_ThornTailRelated01A0);
            triggerIsSet = mainGetBit(triggerGameBit);
            if (triggerIsSet != 0) {
                (*gMapEventInterface)
                    ->setObjGroupStatus(obj->anim.mapEventSlot, SHTHORNTAIL_TRIGGER_ACT7_GROUP_BIT, 0);
                runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
                randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
                runtime->idleTimer = (f32)randomTime;
            } else {
                return;
            }
        } else {
            triggerIsSet = mainGetBit(GAMEBIT_SH_ThornTailRelated01A0);
            if ((triggerIsSet == 0) && (objectTriggerIsSet = ObjTrigger_IsSet(obj), objectTriggerIsSet != 0)) {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGERED;
                runtime->behaviorState = SHTHORNTAIL_STATE_TRIGGERED_EVENT;
                (*gMapEventInterface)
                    ->setObjGroupStatus(obj->anim.mapEventSlot, SHTHORNTAIL_TRIGGER_ACT7_GROUP_BIT, 1);
                mainSetBits(SHTHORNTAIL_TRIGGER_ACT7_GAMEBIT, 1);
                return;
            }
        }
        break;
    case 8:
        runtime->talkSeqs = gSHthorntailHerdAct8TalkSeqVariants[3];
    }
    SHthorntail_updateState(obj, runtime);
}

void SHthorntail_updateSleepyVariant(GameObject* obj, SHthorntailState* runtime, SHthorntailPlacement* placement) {
    GameObject* player;
    int randomIdleWait;
    u8 playerNear;
    u32 gameBit;
    int triggerIsSet;

    runtime->talkSeqs = gSHthorntailSleepyTalkSeqs;
    player = Obj_GetPlayerObject();
    playerNear = getXZDistanceSquared(&obj->anim.worldPosX, &player->anim.worldPosX) < SHTHORNTAIL_PLAYER_NEAR_DISTANCE_SQ;
    if (placement->talkSeqVariant == 0) {
        gameBit = mainGetBit(GAMEBIT_ITEM_FireflyLantern_Got);
        if (gameBit != 0) {
            gameBit = mainGetBit(GAMEBIT_SH_ThornTailRelated0168);
            if (gameBit != 0) {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_FREEZE_MOTION;
                runtime->freezeFrameCounter = 0;
                playerNear = FALSE;
            } else {
                triggerIsSet = ObjTrigger_IsSet(obj);
                if (triggerIsSet != 0) {
                    runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGERED;
                    mainSetBits(GAMEBIT_SH_ThornTailRelated0CD6, 1);
                }
            }
        } else {
            triggerIsSet = ObjTrigger_IsSet(obj);
            if (triggerIsSet != 0) {
                runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGERED;
                mainSetBits(GAMEBIT_SH_ThornTailRelated0CD5, 1);
            }
        }
    } else {
        gameBit = mainGetBit(GAMEBIT_SH_MetQueen);
        if (gameBit != 0) {
            playerNear = FALSE;
        }
    }
    switch (runtime->behaviorState) {
    case SHTHORNTAIL_STATE_IDLE:
        if (!playerNear) {
            runtime->idleTimer = SHTHORNTAIL_IDLE_COUNTDOWN_TIME;
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE_COUNTDOWN;
        }
        break;
    case SHTHORNTAIL_STATE_IDLE_COUNTDOWN:
        if (playerNear) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        } else {
            runtime->idleTimer = runtime->idleTimer - timeDelta;
            if (runtime->idleTimer <= 0.0f) {
                runtime->behaviorState = SHTHORNTAIL_STATE_FALLING_ASLEEP;
            }
        }
        break;
    case SHTHORNTAIL_STATE_FALLING_ASLEEP:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            if (playerNear) {
                runtime->behaviorState = SHTHORNTAIL_STATE_WAKING_UP;
            } else {
                runtime->snoreState = SHTHORNTAIL_SNORE_EXHALE;
                runtime->behaviorState = SHTHORNTAIL_STATE_SLEEPING;
            }
        }
        break;
    case SHTHORNTAIL_STATE_SLEEPING:
        if (playerNear) {
            runtime->behaviorState = SHTHORNTAIL_STATE_WAKING_UP;
        } else {
            ((void (*)(GameObject*, SHthorntailState*))SHthorntail_updateSnoring)(obj, runtime);
        }
        break;
    case SHTHORNTAIL_STATE_WAKING_UP:
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (f32)randomIdleWait;
        }
        break;
    }
}

void SHthorntail_updateHerdVariant(GameObject* obj, SHthorntailState* runtime, SHthorntailPlacement* placement) {
    int linkedEventPending;
    u32 gameBit;
    int randomIdleWait;
    SHthorntailDataTables* tables;

    tables = SHTHORNTAIL_DATA_TABLES;
    runtime->talkSeqs = tables->herdTalkSeqs;
    switch (runtime->mapAct) {
    case 1:
        runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct1TalkSeqVariants[0], placement->talkSeqVariant);
        break;
    case 2:
        gameBit = mainGetBit(GAMEBIT_Tricky_Learned_Distract);
        if (gameBit != 0) {
            runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct2SetTalkSeqVariants[0], placement->talkSeqVariant);
        } else {
            runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct2ClearTalkSeqVariants[0], placement->talkSeqVariant);
        }
        break;
    case 3:
        gameBit = mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got);
        if (gameBit != 0) {
            runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct3SetTalkSeqVariants[0], placement->talkSeqVariant);
        } else {
            runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct3ClearTalkSeqVariants[0], placement->talkSeqVariant);
        }
        break;
    case 5:
        gameBit = mainGetBit(GAMEBIT_SH_ThornTailRelated023D);
        if (gameBit == 0) {
            runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct5ClearTalkSeqVariants[0], placement->talkSeqVariant);
        }
        break;
    case 6:
        linkedEventPending = ((int (*)(GameObject*))SHthorntail_HasNearbyPendingEventObject)(obj);
        if (linkedEventPending != 0) {
            runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
            return;
        }
        if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
            Sfx_PlayFromObject(NULL, SHTHORNTAIL_SFX_EVENT_RESUME);
            runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
            randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
            runtime->idleTimer = (f32)randomIdleWait;
        }
        gameBit = mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got);
        if (gameBit == 0) {
            runtime->talkSeqs = gSHthorntailHerdAct6TalkSeqs;
        }
        break;
    case 8:
        runtime->talkSeqs = SHthorntail_talkSeqVariant(tables->herdAct8TalkSeqVariants[0], placement->talkSeqVariant);
        break;
    }
    SHthorntail_updateState(obj, runtime);
}

u32 SHthorntail_animEventCallback(GameObject* obj, int unused, ObjSeqState* seq) {
    SHthorntailState* runtime;
    int randomIdleWait;
    int turning;
    int inSequence;
    int talkSeqStarted;

    runtime = obj->extra;
    inSequence = runtime->behaviorFlags & SHTHORNTAIL_FLAG_IN_SEQUENCE;
    if (inSequence == 0) {
        Sfx_StopObjectChannel(obj, SHTHORNTAIL_SFX_STOP_CHANNEL);
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomIdleWait = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)randomIdleWait;
        runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_TRIGGERED;
        runtime->behaviorFlags = runtime->behaviorFlags | (SHTHORNTAIL_FLAG_IN_SEQUENCE | SHTHORNTAIL_FLAG_FREEZE_MOTION);
        runtime->freezeFrameCounter = 0;
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | SHTHORNTAIL_HITBOX_FLAG_FREEZE_FRAME;
    }
    talkSeqStarted = runtime->behaviorFlags & SHTHORNTAIL_FLAG_TALK_SEQ_STARTED;
    if (talkSeqStarted != 0) {
        turning = dll_2E_updateSequenceTurn(obj, seq, &runtime->moveLib, 0, 0);
        if (turning != 0) {
            return 0;
        }
        seq->flags &= ~OBJSEQ_FLAG_TEXTURE_ANIM_TRACKS;
        characterDoEyeAnims(obj, &runtime->eyeAnimState);
    }
    runtime->pathState.subtype = 0;
    objAudioDispatchAnimEvents(obj, &seq->animEvents, SHTHORNTAIL_ANIM_AUDIO_TYPE, runtime->renderPathPoints,
                               &runtime->pathState, 1.0f, 1.0f);
    return 0;
}

int SHthorntail_getExtraSize(void) {
    return sizeof(SHthorntailState);
}

void SHthorntail_free(GameObject* obj) {
    SHthorntailPlacement* placement;
    u32 pathOwnerIdent;

    placement = SHTHORNTAIL_PLACEMENT(obj);
    pathOwnerIdent = gSHthorntailPathOwnerIdent;
    if (pathOwnerIdent == placement->ident) {
        gSHthorntailPathOwnerIdent = SHTHORNTAIL_PATH_OWNER_NONE;
    }
    objFreeObjectType(obj, SHTHORNTAIL_OBJECT_GROUP);
}

void SHthorntail_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    SHthorntailState* runtime;
    int pointIndex;

    runtime = obj->extra;
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    dll_2E_setTargetFromPathPoint(obj, &runtime->moveLib, 0);
    pointIndex = 0;
    do {
        ObjPath_GetPointWorldPosition(obj, pointIndex, &runtime->renderPathPoints[pointIndex].x,
                                      &runtime->renderPathPoints[pointIndex].y,
                                      &runtime->renderPathPoints[pointIndex].z, 0);
        pointIndex = pointIndex + 1;
    } while (pointIndex < SHTHORNTAIL_PATH_POINT_COUNT);
}

static void SHthorntail_stepPathControl(GameObject* obj, SHthorntailState* runtime) {
    obj->anim.velocityY = -(SHTHORNTAIL_GRAVITY * timeDelta - obj->anim.velocityY);
    (*gPathControlInterface)->update(obj, &runtime->pathState, timeDelta);
    (*gPathControlInterface)->apply(obj, &runtime->pathState);
    (*gPathControlInterface)->advance(obj, &runtime->pathState, timeDelta);
    obj->anim.rotY = runtime->pathState.tiltPitch;
    obj->anim.rotZ = runtime->pathState.tiltRoll;
}

void SHthorntail_update(GameObject* obj) {
    SHthorntailDataTables* tables;
    SHthorntailState* runtime;
    SHthorntailPlacement* placement;
    int i;
    u8 hitResult;
    ObjHitReactEntry* hitReactEntries;
    int moveComplete;
    int talkSeqIndex;
    int visible;
    int triggered;
    s32 pathOwnerIdent;
    f32 negSinFacing;
    f32 negCosFacing;
    f32 homeDistance;
    ObjAnimEventList animEvents;
    PartFxSpawnParams effectParams;

    tables = SHTHORNTAIL_DATA_TABLES;
    runtime = obj->extra;
    placement = SHTHORNTAIL_PLACEMENT(obj);
    if (runtime->behaviorState == SHTHORNTAIL_STATE_SLEEPING) {
        if (runtime->sleepEffectTimer <= 0.0f) {
            if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                ObjPath_GetPointWorldPosition(obj, SHTHORNTAIL_SLEEP_EFFECT_POINT, &effectParams.posX,
                                              &effectParams.posY, &effectParams.posZ, 0);
                (*gPartfxInterface)
                    ->spawnObject(obj, SHTHORNTAIL_PARTFX_SLEEP, &effectParams, SHTHORNTAIL_PARTFX_SLEEP_FLAGS, -1,
                                  NULL);
            }
            runtime->sleepEffectTimer = SHTHORNTAIL_SLEEP_EFFECT_TIME;
        }
        runtime->sleepEffectTimer = runtime->sleepEffectTimer - timeDelta;
    }
    runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_IN_SEQUENCE;
    if ((SHTHORNTAIL_STATE_ENTRY(u8, tables->stateFlags, runtime->behaviorState) & SHTHORNTAIL_STATE_FLAG_ASLEEP) != 0) {
        hitReactEntries = tables->asleepHitReactEntries;
    } else {
        hitReactEntries = tables->hitReactEntries;
    }
    hitResult = ObjHitReact_Update(obj, hitReactEntries, SHTHORNTAIL_HIT_REACT_ENTRY_COUNT, runtime->hitReactState,
                                   &runtime->hitReactStepScale);
    runtime->hitReactState = hitResult;
    if (hitResult == 0) {
        runtime->mapAct = mapEventGetMapAct(obj->anim.mapEventSlot);
        switch (placement->variant) {
        case SHTHORNTAIL_VARIANT_HERD:
            SHthorntail_updateHerdVariant(obj, runtime, placement);
            break;
        case SHTHORNTAIL_VARIANT_SLEEPY:
            SHthorntail_updateSleepyVariant(obj, runtime, placement);
            break;
        case SHTHORNTAIL_VARIANT_TRIGGER:
            SHthorntail_updateTriggerVariant(obj, runtime);
            break;
        case SHTHORNTAIL_VARIANT_STORY:
            SHthorntail_updateStoryVariant(obj, runtime);
            break;
        }
        if ((SHTHORNTAIL_STATE_ENTRY(u8, tables->stateFlags, runtime->behaviorState) & SHTHORNTAIL_STATE_FLAG_HITBOX_ACTIVE) != 0) {
            obj->anim.resetHitboxFlags |= SHTHORNTAIL_HITBOX_FLAG_ACTIVE;
        } else {
            obj->anim.resetHitboxFlags &= ~SHTHORNTAIL_HITBOX_FLAG_ACTIVE;
            obj->anim.resetHitboxFlags &= ~SHTHORNTAIL_HITBOX_FLAG_FREEZE_FRAME;
        }
        if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_FREEZE_MOTION) != 0) {
            if (++runtime->freezeFrameCounter > SHTHORNTAIL_FREEZE_FRAME_COUNT) {
                runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_FREEZE_MOTION;
            } else {
                obj->anim.resetHitboxFlags |= SHTHORNTAIL_HITBOX_FLAG_FREEZE_FRAME;
            }
        }
        if (obj->anim.currentMove != SHTHORNTAIL_STATE_ENTRY(s16, tables->stateMoveIds, runtime->behaviorState)) {
            ObjAnim_SetCurrentMove(obj, SHTHORNTAIL_STATE_ENTRY(s16, tables->stateMoveIds, runtime->behaviorState), 0.0f, 0);
            runtime->storedFacingAngle = obj->anim.rotX;
        }
        moveComplete =
            ObjAnim_AdvanceCurrentMove(obj, SHTHORNTAIL_STATE_ENTRY(f32, tables->stateMoveStepScales, runtime->behaviorState), timeDelta, &animEvents);
        if (moveComplete != 0) {
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        } else {
            runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_MOVE_COMPLETE;
        }
        if ((SHTHORNTAIL_STATE_ENTRY(u8, tables->stateFlags, runtime->behaviorState) & SHTHORNTAIL_STATE_FLAG_ROOT_MOTION) != 0) {
            if ((runtime->behaviorFlags & SHTHORNTAIL_FLAG_MOVE_COMPLETE) != 0) {
                runtime->storedFacingAngle = obj->anim.rotX;
            }
            negSinFacing = -mathSinf((3.1415927f * (f32)runtime->storedFacingAngle) / 32768.0f);
            negCosFacing = -mathCosf((3.1415927f * (f32)runtime->storedFacingAngle) / 32768.0f);
            obj->anim.localPosX = negSinFacing * -animEvents.rootDeltaZ + obj->anim.localPosX;
            obj->anim.localPosZ = negCosFacing * -animEvents.rootDeltaZ + obj->anim.localPosZ;
            obj->anim.localPosX = negCosFacing * -animEvents.rootDeltaX + obj->anim.localPosX;
            obj->anim.localPosZ = negSinFacing * animEvents.rootDeltaX + obj->anim.localPosZ;
            obj->anim.rotX += animEvents.rootPitch;
        }
        for (i = 0; i < animEvents.triggerCount; i = i + 1) {
            if (animEvents.triggeredIds[i] == SHTHORNTAIL_ANIM_EVENT_PRIMARY) {
                if (SHTHORNTAIL_STATE_ENTRY(u16, tables->statePrimaryEventSfx, runtime->behaviorState) != 0) {
                    Sfx_PlayFromObject(obj, SHTHORNTAIL_STATE_ENTRY(u16, tables->statePrimaryEventSfx, runtime->behaviorState));
                }
            } else if ((animEvents.triggeredIds[i] == SHTHORNTAIL_ANIM_EVENT_SECONDARY) &&
                       (SHTHORNTAIL_STATE_ENTRY(u8, tables->stateSecondaryEventSfx, runtime->behaviorState) != 0)) {
                Sfx_PlayFromObject(obj, SHTHORNTAIL_STATE_ENTRY(u8, tables->stateSecondaryEventSfx, runtime->behaviorState));
            }
        }
        objAudioDispatchAnimEvents(obj, &animEvents, SHTHORNTAIL_ANIM_AUDIO_TYPE, runtime->renderPathPoints,
                                   &runtime->pathState, 1.0f, 1.0f);
        if ((SHTHORNTAIL_STATE_ENTRY(u8, tables->stateFlags, runtime->behaviorState) & SHTHORNTAIL_STATE_FLAG_NO_LOOK_AT) != 0) {
            runtime->moveLib.modeBits = runtime->moveLib.modeBits & ~SHTHORNTAIL_LOOK_AT_ENABLED;
        } else {
            runtime->moveLib.modeBits = runtime->moveLib.modeBits | SHTHORNTAIL_LOOK_AT_ENABLED;
        }
        dll_2E_updateLookAt(obj, &runtime->moveLib);
        if ((SHTHORNTAIL_STATE_ENTRY(u8, tables->stateFlags, runtime->behaviorState) & SHTHORNTAIL_STATE_FLAG_ASLEEP) != 0) {
            characterCloseEyes(obj, &runtime->eyeAnimState);
        } else {
            characterDoEyeAnims(obj, &runtime->eyeAnimState);
        }
        runtime->behaviorFlags = runtime->behaviorFlags & ~SHTHORNTAIL_FLAG_TALK_SEQ_STARTED;
        if (((runtime->behaviorFlags & SHTHORNTAIL_FLAG_TRIGGERED) == 0) &&
            (triggered = ObjTrigger_IsSet(obj), triggered != 0)) {
            talkSeqIndex = randomGetRange(1, runtime->talkSeqs[0]);
            runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TALK_SEQ_STARTED;
            (*gObjectTriggerInterface)->runSequence(runtime->talkSeqs[talkSeqIndex], obj, -1);
        }
        if (placement->leashRadius != 0) {
            homeDistance = getXZDistanceSquared(&obj->anim.worldPosX, &placement->homePosition.x);
            if ((homeDistance > (f32)(placement->leashRadius * placement->leashRadius)) &&
                (visible = ViewFrustum_IsSphereVisible(&obj->anim.localPosX,
                                                       obj->anim.hitboxScale * obj->anim.rootMotionScale),
                 visible == 0)) {
                obj->anim.rotX = getAngle(obj->anim.localPosX - placement->homePosition.x,
                                          obj->anim.localPosZ - placement->homePosition.z);
            }
        }
        runtime->pathState.subtype = 1;
        pathOwnerIdent = gSHthorntailPathOwnerIdent;
        if (pathOwnerIdent == SHTHORNTAIL_PATH_OWNER_NONE) {
            gSHthorntailPathOwnerIdent = SHTHORNTAIL_PLACEMENT(obj)->ident;
            SHthorntail_stepPathControl(obj, runtime);
        } else {
            if ((u32)pathOwnerIdent == (u32)SHTHORNTAIL_PLACEMENT(obj)->ident) {
                gSHthorntailPathOwnerIdent = SHTHORNTAIL_PATH_OWNER_NONE;
            }
            if ((SHTHORNTAIL_STATE_WALK_START <= runtime->behaviorState) &&
                (runtime->behaviorState <= SHTHORNTAIL_STATE_WALK_STOP)) {
                SHthorntail_stepPathControl(obj, runtime);
            } else {
                (*gPathControlInterface)->attachObject(obj, &runtime->pathState);
            }
        }
    }
}

void SHthorntail_init(GameObject* obj, const SHthorntailPlacement* placement) {
    SHthorntailState* runtime = obj->extra;
    ObjModel* model;
    int randomTime;
    CurvesCollisionState* pathState;
    SHthorntailPathSourceTypes pathSourceTypes = sSHthorntailPathSourceTypes;

    obj->anim.rotX = placement->initialFacing << 8;
    switch (placement->variant) {
    case SHTHORNTAIL_VARIANT_HERD:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)randomTime;
        break;
    case SHTHORNTAIL_VARIANT_SLEEPY:
        runtime->snoreState = SHTHORNTAIL_SNORE_EXHALE;
        runtime->behaviorState = SHTHORNTAIL_STATE_SLEEPING;
        break;
    case SHTHORNTAIL_VARIANT_TRIGGER:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)randomTime;
        break;
    case SHTHORNTAIL_VARIANT_STORY:
        runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
        randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN, SHTHORNTAIL_IDLE_WAIT_MAX);
        runtime->idleTimer = (f32)randomTime;
        break;
    }
    obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase * ((f32)placement->scale / 1000.0f);
    model = Obj_GetActiveModel(obj);
    modelInitBones(obj->anim.rootMotionScale, model);
    pathState = &runtime->pathState;
    (*gPathControlInterface)->init(pathState, SHTHORNTAIL_PATH_CONTROL_MODE, SHTHORNTAIL_PATH_CONTROL_FLAGS, 0);
    (*gPathControlInterface)
        ->setup(pathState, SHTHORNTAIL_PATH_POINT_COUNT, gSHthorntailPathPoints, gSHthorntailPathRadii,
                &pathSourceTypes);
    (*gPathControlInterface)->attachObject(obj, pathState);
    obj->animEventCallback = SHthorntail_animEventCallback;
    dll_2E_initState(obj, &runtime->moveLib, SHTHORNTAIL_LOOK_AT_MIN_YAW, SHTHORNTAIL_LOOK_AT_MAX_YAW,
                     SHTHORNTAIL_LOOK_AT_POINT_COUNT);
    dll_2E_setReattackDelay(&runtime->moveLib, SHTHORNTAIL_REATTACK_DELAY_BASE, SHTHORNTAIL_REATTACK_DELAY_MIN);
    objAddObjectType(obj, SHTHORNTAIL_OBJECT_GROUP);
}
