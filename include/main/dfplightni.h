#ifndef MAIN_DFPLIGHTNI_H_
#define MAIN_DFPLIGHTNI_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/dfppowersl.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

#define DFPLIGHTNI_OBJECT_DEF_ID 0x0345
#define DFPLIGHTNI_DLL_ID 0x023B
#define DFPLIGHTNI_CLASS_ID 0x0030
#define DFPLIGHTNI_OBJECT_DEF_SIZE 0xA0
#define DFPLIGHTNI_PLACEMENT_SIZE 0x24

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

#define DFPPOWERSL_SPAWN_OBJECT_ID 0x39e
#define DFPPOWERSL_SPAWN_COUNT 0x14

typedef struct DfpLightniMapData {
  ObjPlacement base;
  s8 angleIndex;
  s8 delayTicks;
  s16 radiusX;
  s16 radiusY;
  u8 pad1E[0x20 - 0x1E];
  s16 eventId;
  u8 pad22[0x24 - 0x22];
} DfpLightniMapData;

typedef struct DfpLightniState {
  void *effectHandle;
  f32 timer;
  f32 triggerTime;
  f32 radiusX;
  f32 radiusY;
  s16 angleIndex;
  s16 delayFrames;
  s32 eventId;
} DfpLightniState;

typedef struct DfpLightniObject {
  u8 pad00[0x0C];
  f32 position[3];
  u8 pad18[0xB8 - 0x18];
  DfpLightniState *state;
} DfpLightniObject;

STATIC_ASSERT(offsetof(DfpLightniMapData, angleIndex) == 0x18);
STATIC_ASSERT(offsetof(DfpLightniMapData, delayTicks) == 0x19);
STATIC_ASSERT(offsetof(DfpLightniMapData, radiusX) == 0x1A);
STATIC_ASSERT(offsetof(DfpLightniMapData, radiusY) == 0x1C);
STATIC_ASSERT(offsetof(DfpLightniMapData, eventId) == 0x20);

STATIC_ASSERT(sizeof(DfpLightniState) == 0x1C);
STATIC_ASSERT(offsetof(DfpLightniState, effectHandle) == 0x00);
STATIC_ASSERT(offsetof(DfpLightniState, timer) == 0x04);
STATIC_ASSERT(offsetof(DfpLightniState, triggerTime) == 0x08);
STATIC_ASSERT(offsetof(DfpLightniState, radiusX) == 0x0C);
STATIC_ASSERT(offsetof(DfpLightniState, radiusY) == 0x10);
STATIC_ASSERT(offsetof(DfpLightniState, angleIndex) == 0x14);
STATIC_ASSERT(offsetof(DfpLightniState, delayFrames) == 0x16);
STATIC_ASSERT(offsetof(DfpLightniState, eventId) == 0x18);

STATIC_ASSERT(offsetof(DfpLightniObject, position) == 0x0C);
STATIC_ASSERT(offsetof(DfpLightniObject, state) == 0xB8);

extern ObjectDescriptor gDfplightniObjDescriptor;

int DFP_Lightni_getExtraSize(void);
void DFP_Lightni_free(DfpLightniObject *obj);
void DFP_Lightni_render(DfpLightniObject *obj);
void DFP_Lightni_update(DfpLightniObject *obj);
void DFP_Lightni_init(DfpLightniObject *obj,DfpLightniMapData *mapData);
int dfppowersl_spawnSeqObjectsOnHit(DfpPowerSlObject *obj);

#endif /* MAIN_DFPLIGHTNI_H_ */
