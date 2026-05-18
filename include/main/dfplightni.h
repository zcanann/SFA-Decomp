#ifndef MAIN_DFPLIGHTNI_H_
#define MAIN_DFPLIGHTNI_H_

#include "ghidra_import.h"
#include "main/dfppowersl.h"
#include "main/object_descriptor.h"

#define DFPLIGHTNI_EVENT_TIMER_GAMEBIT 0x5e5
#define DFPLIGHTNI_BLOCKED_GAMEBIT 0xe57
#define DFPLIGHTNI_SFX_ID 0x4c3
#define DFPLIGHTNI_SFX_MAX_COUNT 2

#define DFPLIGHTNI_RANDOM_TIMER_MIN 0
#define DFPLIGHTNI_RANDOM_TIMER_MAX 100
#define DFPLIGHTNI_RANDOM_XZ_MIN -200
#define DFPLIGHTNI_RANDOM_XZ_MAX 200
#define DFPLIGHTNI_RANDOM_Y_MIN 100
#define DFPLIGHTNI_RANDOM_Y_MAX 300

#define DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES 10
#define DFPLIGHTNI_ANGLE_STEP 0xc
#define DFPLIGHTNI_EFFECT_ANGLE_MASK 0xff

#define DFPLIGHTNI_OBJECT_POS_X_OFFSET 0xc
#define DFPLIGHTNI_OBJECT_POS_Y_OFFSET 0x10
#define DFPLIGHTNI_OBJECT_POS_Z_OFFSET 0x14
#define DFPLIGHTNI_OBJECT_STATE_OFFSET 0xb8

#define DFPPOWERSL_SPAWN_OBJECT_ID 0x39e
#define DFPPOWERSL_SPAWN_COUNT 0x14

typedef struct DfpLightniMapData {
  u8 pad00[0x18];
  s8 angleIndex;
  s8 delayTicks;
  s16 radiusX;
  s16 radiusY;
  u8 pad1E[0x20 - 0x1E];
  s16 eventId;
  u8 pad22[0x24 - 0x22];
} DfpLightniMapData;

typedef struct DfpLightniState {
  u32 effectHandle;
  f32 timer;
  f32 triggerTime;
  f32 radiusX;
  f32 radiusY;
  s16 angleIndex;
  s16 delayFrames;
  s32 eventId;
} DfpLightniState;

extern ObjectDescriptor gDfplightniObjDescriptor;

int dfplightni_getExtraSize(void);
void dfplightni_free(u8 *obj);
void dfplightni_render(u8 *obj);
void dfplightni_update(u8 *obj);
void dfplightni_init(u8 *obj,DfpLightniMapData *mapData);
int dfppowersl_spawnSeqObjectsOnHit(u8 *obj);

#endif /* MAIN_DFPLIGHTNI_H_ */
