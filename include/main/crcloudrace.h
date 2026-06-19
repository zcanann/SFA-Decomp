#ifndef MAIN_CRCLOUDRACE_H_
#define MAIN_CRCLOUDRACE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

#define CRCLOUDRACE_DRAG_ROCK_MAP_ID 0x0C

#define CRCLOUDRACE_GAMEBIT_START_LATCH_A 0xE24
#define CRCLOUDRACE_GAMEBIT_START_LATCH_B 0x0E8
#define CRCLOUDRACE_GAMEBIT_START_LATCH_C 0x038
#define CRCLOUDRACE_GAMEBIT_EFFECT_CLEAR 0xDCB
#define CRCLOUDRACE_GAMEBIT_COMPLETION_EVENT 0xDCA
#define CRCLOUDRACE_GAMEBIT_DRAG_ROCK_CLEARED 0x458
#define CRCLOUDRACE_GAMEBIT_IN_FINISH_VOLUME 0x499
#define CRCLOUDRACE_GAMEBIT_ABORT_TRIGGER 0x2E8
#define CRCLOUDRACE_GAMEBIT_RACE_CAN_FINISH 0x4A9
#define CRCLOUDRACE_GAMEBIT_RACE_STARTED 0x49D
#define CRCLOUDRACE_GAMEBIT_RACE_ACTIVE 0x497
#define CRCLOUDRACE_GAMEBIT_TOTEM_GATE 0x4A0
#define CRCLOUDRACE_GAMEBIT_TOTEM_LATCH 0x4BA

#define CRCLOUDRACE_RESET_BIT_D73 0xD73
#define CRCLOUDRACE_RESET_BIT_983 0x983
#define CRCLOUDRACE_RESET_BIT_E23 0xE23
#define CRCLOUDRACE_RESET_BIT_E1D 0xE1D
#define CRCLOUDRACE_RESET_BIT_DB8 0xDB8
#define CRCLOUDRACE_RESET_BIT_984 0x984

#define CRCLOUDRACE_ENVFX_CLEAR_A 0x174
#define CRCLOUDRACE_ENVFX_CLEAR_B 0x1E1
#define CRCLOUDRACE_NEARBY_TOTEM_GROUP 0x1E
#define CRCLOUDRACE_COMPLETION_ANIM_EVENT 1
#define CRCLOUDRACE_COUNTDOWN_FRAMES 10

#define CRCLOUDRACE_STATE_FLAG_COMPLETION_CALLBACK 0x01

typedef enum CrCloudRacePhase {
  CRCLOUDRACE_PHASE_IDLE = 0,
  CRCLOUDRACE_PHASE_START = 2,
  CRCLOUDRACE_PHASE_RACING = 3,
  CRCLOUDRACE_PHASE_ABORT = 4,
  CRCLOUDRACE_PHASE_RESET_TO_START = 5,
  CRCLOUDRACE_PHASE_COUNTDOWN = 7,
  CRCLOUDRACE_PHASE_RELOAD_DRAG_ROCK = 8,
} CrCloudRacePhase;

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
  int (*animEventCallback)(int obj, int unused, ObjAnimUpdateState *animUpdate);
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
STATIC_ASSERT(offsetof(CrCloudRaceObject, animEventCallback) == 0xBC);
STATIC_ASSERT(offsetof(CrCloudRaceObject, unkF4) == 0xF4);
STATIC_ASSERT(offsetof(CrCloudRaceObject, unkF8) == 0xF8);

extern ObjectDescriptor gCrCloudRaceObjDescriptor;

int crcloudrace_getExtraSize(void);
int crcloudrace_getObjectTypeId(void);
void crcloudrace_free(void);
void crcloudrace_render(u32 param_1,u32 param_2,u32 param_3,
                        u32 param_4,u32 param_5,char visible);
void crcloudrace_hitDetect(void);
void crcloudrace_update(CrCloudRaceObject *obj);
void crcloudrace_init(CrCloudRaceObject *obj);
int crcloudrace_completionCallback(int obj, int unused, ObjAnimUpdateState *animUpdate);
void crcloudrace_release(void);
void crcloudrace_initialise(void);

#endif /* MAIN_CRCLOUDRACE_H_ */
