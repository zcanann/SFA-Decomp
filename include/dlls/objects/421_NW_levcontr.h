#ifndef DLLS_OBJECTS_421_NW_LEVCONTR_H_
#define DLLS_OBJECTS_421_NW_LEVCONTR_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"

#define NW_LEVEL_CONTROL_DATA_SIZE 0x134
#define NW_LEVEL_CONTROL_SEQUENCE_ENTRY_COUNT 7
#define NW_LEVEL_CONTROL_SKY_RAMP_VALUE_COUNT 28

typedef enum NwLevelControlMode {
    NW_LEVEL_CONTROL_MODE_WAIT_START = 0,
    NW_LEVEL_CONTROL_MODE_INIT_START = 1,
    NW_LEVEL_CONTROL_MODE_WALK_TABLE = 2,
    NW_LEVEL_CONTROL_MODE_WALK_FINAL = 8,
    NW_LEVEL_CONTROL_MODE_WAIT_PARENT_SLACK = 9,
    NW_LEVEL_CONTROL_MODE_TIMER_STEP = 10,
    NW_LEVEL_CONTROL_MODE_CLEANUP = 0xB,
    NW_LEVEL_CONTROL_MODE_RESCUE_RETRIGGER = 0xC,
} NwLevelControlMode;

typedef struct NwLevelControlState {
    f32 hintCountdown;
    u8 mode;
    u8 timerSeconds;
    u8 unknown06[2];
    u32 flags;
    u8 sequenceId;
    u8 nextMode;
    u8 tableIndex;
    u8 unknown0F;
    s16 dayNightMusicId;
    u8 unknown12[2];
} NwLevelControlState;

STATIC_ASSERT(sizeof(NwLevelControlState) == 0x14);
STATIC_ASSERT(offsetof(NwLevelControlState, hintCountdown) == 0x00);
STATIC_ASSERT(offsetof(NwLevelControlState, mode) == 0x04);
STATIC_ASSERT(offsetof(NwLevelControlState, timerSeconds) == 0x05);
STATIC_ASSERT(offsetof(NwLevelControlState, unknown06) == 0x06);
STATIC_ASSERT(offsetof(NwLevelControlState, flags) == 0x08);
STATIC_ASSERT(offsetof(NwLevelControlState, sequenceId) == 0x0C);
STATIC_ASSERT(offsetof(NwLevelControlState, nextMode) == 0x0D);
STATIC_ASSERT(offsetof(NwLevelControlState, tableIndex) == 0x0E);
STATIC_ASSERT(offsetof(NwLevelControlState, unknown0F) == 0x0F);
STATIC_ASSERT(offsetof(NwLevelControlState, dayNightMusicId) == 0x10);
STATIC_ASSERT(offsetof(NwLevelControlState, unknown12) == 0x12);

typedef struct NwLevelControlData {
    s32 targetObjectIds[NW_LEVEL_CONTROL_SEQUENCE_ENTRY_COUNT];
    s32 sequenceIds[NW_LEVEL_CONTROL_SEQUENCE_ENTRY_COUNT];
    s32 nextModes[NW_LEVEL_CONTROL_SEQUENCE_ENTRY_COUNT];
    s16 skyRampA[NW_LEVEL_CONTROL_SKY_RAMP_VALUE_COUNT];
    s16 skyRampB[NW_LEVEL_CONTROL_SKY_RAMP_VALUE_COUNT];
    s16 skyRampC[NW_LEVEL_CONTROL_SKY_RAMP_VALUE_COUNT];
    s16 skyRampD[NW_LEVEL_CONTROL_SKY_RAMP_VALUE_COUNT];
} NwLevelControlData;

extern NwLevelControlData gNwLevelControlData;
extern ObjectDescriptor gNWLevelControlObjDescriptor;

int nwLevelControl_advanceSequenceTable(NwLevelControlState* state);
int nwLevelControl_getExtraSize(void);
void nwLevelControl_free(GameObject* obj);
void nwLevelControl_update(GameObject* obj);
void nwLevelControl_init(GameObject* obj);

#endif /* DLLS_OBJECTS_421_NW_LEVCONTR_H_ */
