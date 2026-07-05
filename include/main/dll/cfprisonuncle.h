#ifndef MAIN_DLL_DLL_14F_H_
#define MAIN_DLL_DLL_14F_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/object_descriptor.h"
#include "main/objanim_internal.h"

#define MAGICPLANT_DLL_ID 0x00FE
#define MAGICPLANT_CLASS_ID 0x0065
#define MAGICPLANT_DEF_ID 0x04FE
#define MAGICPLANT_OBJECT_DEF_BYTES 0x100
#define MAGICPLANT_PLACEMENT_BYTES 0x20
#define MAGICPLANT_EXTRA_STATE_BYTES 0x10
#define MAGICPLANT_OBJECT_TYPE_BASE 0x400
#define MAGICPLANT_OBJECT_TYPE_MODEL_SHIFT 11
#define MAGICPLANT_OBJECT_FLAGS_CHILD_EFFECTS 0x2000

typedef struct MagicPlantSetup {
  u8 pad00[0x14];
  int eventId;
  u16 eventDuration;
  u8 pad1A;
  u8 variant;
  u8 modelIndex;
  u8 yawByte;
  u8 pad1E[MAGICPLANT_PLACEMENT_BYTES - 0x1E];
} MagicPlantSetup;

typedef struct MagicPlantState {
  u32 childObject;
  f32 animProgress;
  f32 animStepScale;
  s16 idleTimer;
  u8 pad0E;
  s8 mode;
} MagicPlantState;

typedef struct MagicPlantObject {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  MagicPlantState *state;
  void *seqCallback;
  u8 padC0[0xEB - 0xC0];
  u8 childLinkActive;
} MagicPlantObject;

enum MagicPlantMode {
  MAGICPLANT_MODE_WAIT_FOR_EVENT,
  MAGICPLANT_MODE_ACTIVE,
  MAGICPLANT_MODE_FADE_OUT,
  MAGICPLANT_MODE_FADE_IN,
  MAGICPLANT_MODE_HIT_REACT
};

STATIC_ASSERT(sizeof(MagicPlantSetup) == MAGICPLANT_PLACEMENT_BYTES);
STATIC_ASSERT(sizeof(MagicPlantState) == MAGICPLANT_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(MagicPlantState, childObject) == 0x00);
STATIC_ASSERT(offsetof(MagicPlantState, animProgress) == 0x04);
STATIC_ASSERT(offsetof(MagicPlantState, animStepScale) == 0x08);
STATIC_ASSERT(offsetof(MagicPlantState, idleTimer) == 0x0c);
STATIC_ASSERT(offsetof(MagicPlantState, mode) == 0x0f);
STATIC_ASSERT(offsetof(MagicPlantSetup, eventId) == 0x14);
STATIC_ASSERT(offsetof(MagicPlantSetup, eventDuration) == 0x18);
STATIC_ASSERT(offsetof(MagicPlantSetup, variant) == 0x1b);
STATIC_ASSERT(offsetof(MagicPlantSetup, modelIndex) == 0x1c);
STATIC_ASSERT(offsetof(MagicPlantSetup, yawByte) == 0x1d);
STATIC_ASSERT(offsetof(MagicPlantObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(MagicPlantObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(MagicPlantObject, state) == 0xB8);
STATIC_ASSERT(offsetof(MagicPlantObject, seqCallback) == 0xBC);
STATIC_ASSERT(offsetof(MagicPlantObject, childLinkActive) == 0xEB);

void MagicPlant_updateActive(int obj, MagicPlantSetup *setup, MagicPlantState *state);
void MagicPlant_spawnChild(int obj,int objectId);
void FUN_8017f7ec(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int *param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int MagicPlant_getExtraSize(void);
u32 MagicPlant_getObjectTypeId(MagicPlantObject *obj);
void MagicPlant_free(int obj, int param_2);
void MagicPlant_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void MagicPlant_update(int obj);
void MagicPlant_init(int obj, MagicPlantSetup *setup);
void FUN_8017fa14(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u16 param_10);
u32 FUN_8017fba8(void);
void FUN_8017fbe0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_8017fccc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8017fd40(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
typedef struct TrickyWarpState {
  u8 patchGroup;
  u8 active;
  u8 pad02[2];
  int curveNodeIds[0x18];
} TrickyWarpState;

int trickywarp_getExtraSize(void);
void trickywarp_free(int obj);
void trickywarp_update(int obj);
int fn_8017FFD0(int obj, TrickyWarpState *state);
void trickywarp_init(s16 *obj, u8 *param_2);
void FUN_801804a0(short *param_1,int param_2);
void FUN_801804a4(int param_1);
void FUN_801804d8(int param_1,u32 param_2,u8 *param_3,int param_4,int param_5);
void FUN_801804dc(u32 param_1,u32 param_2,u8 *param_3,int param_4,int param_5);
void trickyguard_update();
void trickyguard_init(s16 *obj, u8 *param_2);
void StayPoint_update(int obj);
void StayPoint_init(u16 *obj);
int duster_getExtraSize(void);
void duster_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void duster_hitDetect(int obj);
void duster_update(int obj);
void duster_init(int obj, u8 *params);
void FUN_80180700(int param_1);
void FUN_801807cc(int param_1);
void FUN_80180940(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80180984(int *param_1);
void FUN_80180a0c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_801811c8(int param_1,int param_2);
void FUN_801811cc(void);
void FUN_80181a90(int param_1,int param_2);
void FUN_80181b50(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11);
int curvefish_getExtraSize(void);
void curvefish_update(int obj);
void curvefish_init(int obj, u8 *param_2);
void fn_801814D0(int obj, int param_2, u8 *state);

extern ObjectDescriptor gMagicPlantObjDescriptor;
extern ObjectDescriptor gTrickyWarpObjDescriptor;
extern ObjectDescriptor gTrickyGuardObjDescriptor;
extern ObjectDescriptor gStayPointObjDescriptor;
extern ObjectDescriptor gDusterObjDescriptor;
extern ObjectDescriptor gCurveFishObjDescriptor;

#endif /* MAIN_DLL_DLL_14F_H_ */
