#ifndef MAIN_DFPPOWERSL_H_
#define MAIN_DFPPOWERSL_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define DFPPOWERSL_OBJECT_STATE_OFFSET 0xb8
#define DFPPOWERSL_HIT_CALLBACK_OFFSET 0xbc
#define DFPPOWERSL_PARAM_MODE 0x18
#define DFPPOWERSL_PARAM_ACTIVATE_OBJECT_ID 0x1a
#define DFPPOWERSL_PARAM_SPAWN_OBJECT_ID 0x1c
#define DFPPOWERSL_PARAM_EVENT_ID 0x20
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

typedef void (*DfpPowerSlFreeFn)(u8 *obj);
typedef void (*DfpPowerSlActivateFn)(u8 *obj,int objectId);
typedef void (*DfpPowerSlRefreshFn)(int param_1,u8 *obj,int param_3);
typedef void (*DfpPowerSlSpawnFn)(u8 *obj,int objectId,void *params,int param_4,int param_5,void *outObj);
typedef int (*DfpPowerSlHitCallback)(u8 *obj);

extern ObjectDescriptor gDfppowerslObjDescriptor;

int dfppowersl_spawnSeqObjectsOnHit(u8 *obj);
int dfppowersl_getExtraSize(void);
void dfppowersl_free(u8 *obj);
void dfppowersl_render(u8 *obj);
void dfppowersl_update(u8 *obj);
void dfppowersl_init(u8 *obj,u8 *params);

#endif /* MAIN_DFPPOWERSL_H_ */
