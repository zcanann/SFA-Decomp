#ifndef MAIN_DFPPOWERSL_H_
#define MAIN_DFPPOWERSL_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objseq.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

#define DFPPOWERSL_OBJECT_DEF_ID 0x0344
#define DFPPOWERSL_DLL_ID 0x023C
#define DFPPOWERSL_CLASS_ID 0x0030

#define DFPPOWERSL_DEFAULT_PARAM_OBJECT_ID 1
#define DFPPOWERSL_MODE_WORD_SHIFT 8
#define DFPPOWERSL_SPAWN_MODE_PRELOAD 4
#define DFPPOWERSL_SPAWN_MODE_ACTIVE 1
#define DFPPOWERSL_HIT_VOLUME_SLOT 0x13
#define DFPPOWERSL_HIT_VOLUME_ENABLED 1

typedef struct DfpPowerSlState {
  s32 activateObjectId;
  s32 spawnObjectId;
  s32 eventId;
} DfpPowerSlState;

typedef struct DfpPowerSlObject DfpPowerSlObject;

typedef int (*DfpPowerSlHitCallback)(DfpPowerSlObject *obj);

typedef struct DfpPowerSlMapData {
  ObjPlacement base;
  s8 mode;
  u8 pad19;
  s16 activateObjectId;
  s16 spawnObjectId;
  u8 pad1E[0x20 - 0x1E];
  s16 eventId;
} DfpPowerSlMapData;

struct DfpPowerSlObject {
  s16 modeWord;
  u8 pad02[0xB8 - 0x02];
  DfpPowerSlState *state;
  DfpPowerSlHitCallback hitCallback;
};

STATIC_ASSERT(sizeof(DfpPowerSlState) == 0x0C);
STATIC_ASSERT(offsetof(DfpPowerSlState, activateObjectId) == 0x00);
STATIC_ASSERT(offsetof(DfpPowerSlState, spawnObjectId) == 0x04);
STATIC_ASSERT(offsetof(DfpPowerSlState, eventId) == 0x08);

STATIC_ASSERT(offsetof(DfpPowerSlMapData, mode) == 0x18);
STATIC_ASSERT(offsetof(DfpPowerSlMapData, activateObjectId) == 0x1A);
STATIC_ASSERT(offsetof(DfpPowerSlMapData, spawnObjectId) == 0x1C);
STATIC_ASSERT(offsetof(DfpPowerSlMapData, eventId) == 0x20);
STATIC_ASSERT(sizeof(DfpPowerSlMapData) == 0x24);

STATIC_ASSERT(offsetof(DfpPowerSlObject, modeWord) == 0x00);
STATIC_ASSERT(offsetof(DfpPowerSlObject, state) == 0xB8);
STATIC_ASSERT(offsetof(DfpPowerSlObject, hitCallback) == 0xBC);

extern ObjectDescriptor gDfppowerslObjDescriptor;

int dfppowersl_spawnSeqObjectsOnHit(DfpPowerSlObject *obj);
int dfppowersl_getExtraSize(void);
void dfppowersl_free(DfpPowerSlObject *obj);
void dfppowersl_render(DfpPowerSlObject *obj);
void dfppowersl_update(DfpPowerSlObject *obj);
void dfppowersl_init(DfpPowerSlObject *obj,DfpPowerSlMapData *mapData);

#endif /* MAIN_DFPPOWERSL_H_ */
