#ifndef MAIN_CRCLOUDRACE_H_
#define MAIN_CRCLOUDRACE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct CrCloudRaceState {
  u8 unk0[4];
  u8 timer[4];
  u8 phase;
  u8 flags;
  u8 unkA[2];
  u8 effect[4];
} CrCloudRaceState;

typedef struct CrCloudRaceObject {
  u8 unk0[0xb8];
  CrCloudRaceState *state;
  undefined4 (*callback)(void *obj,undefined4 param_2,void *param_3);
  u8 unkC0[0x34];
  int unkF4;
  int unkF8;
} CrCloudRaceObject;

extern ObjectDescriptor gCrCloudRaceObjDescriptor;

int crcloudrace_getExtraSize(void);
int crcloudrace_func08(void);
void crcloudrace_free(void);
void crcloudrace_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible);
void crcloudrace_hitDetect(void);
void crcloudrace_update(CrCloudRaceObject *obj);
void crcloudrace_init(CrCloudRaceObject *obj);
void crcloudrace_release(void);
void crcloudrace_initialise(void);

#endif /* MAIN_CRCLOUDRACE_H_ */
