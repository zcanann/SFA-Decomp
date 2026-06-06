#ifndef MAIN_CRCLOUDRACE_H_
#define MAIN_CRCLOUDRACE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

#define CRCLOUDRACE_STATE_FLAG_COMPLETION_CALLBACK 0x01

typedef struct CrCloudRaceState {
  u8 unk0[4];
  u8 timer[4];
  u8 phase;
  u8 flags;
  u8 unkA[2];
  u8 effect[4];
} CrCloudRaceState;

typedef struct CrCloudRaceObject {
  ObjAnimComponent anim;
  u16 objectFlags;
  u8 unkB2[0xB8 - 0xB2];
  CrCloudRaceState *state;
  undefined4 (*callback)(void *obj,undefined4 param_2,void *param_3);
  u8 unkC0[0x34];
  int unkF4;
  int unkF8;
} CrCloudRaceObject;

STATIC_ASSERT(sizeof(CrCloudRaceState) == 0x10);
STATIC_ASSERT(offsetof(CrCloudRaceState, timer) == 0x04);
STATIC_ASSERT(offsetof(CrCloudRaceState, phase) == 0x08);
STATIC_ASSERT(offsetof(CrCloudRaceState, flags) == 0x09);
STATIC_ASSERT(offsetof(CrCloudRaceState, effect) == 0x0C);

STATIC_ASSERT(offsetof(CrCloudRaceObject, anim) == 0x00);
STATIC_ASSERT(offsetof(CrCloudRaceObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(CrCloudRaceObject, state) == 0xB8);
STATIC_ASSERT(offsetof(CrCloudRaceObject, callback) == 0xBC);
STATIC_ASSERT(offsetof(CrCloudRaceObject, unkF4) == 0xF4);
STATIC_ASSERT(offsetof(CrCloudRaceObject, unkF8) == 0xF8);

extern ObjectDescriptor gCrCloudRaceObjDescriptor;

int crcloudrace_getExtraSize(void);
int crcloudrace_getObjectTypeId(void);
void crcloudrace_free(void);
void crcloudrace_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible);
void crcloudrace_hitDetect(void);
void crcloudrace_update(CrCloudRaceObject *obj);
void crcloudrace_init(CrCloudRaceObject *obj);
void crcloudrace_release(void);
void crcloudrace_initialise(void);

#endif /* MAIN_CRCLOUDRACE_H_ */
