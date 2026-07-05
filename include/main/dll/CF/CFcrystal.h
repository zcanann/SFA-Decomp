#ifndef MAIN_DLL_CF_CFCRYSTAL_H_
#define MAIN_DLL_CF_CFCRYSTAL_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

typedef struct FireFlyLanternSpawnSetup {
  s16 objectType;
  u8 setupType;
  u8 pad03;
  u8 field04;
  u8 field05;
  u8 field06;
  u8 field07;
  f32 x;
  f32 y;
  f32 z;
  u8 pad14[0x18 - 0x14];
  u8 field18;
  u8 field19;
  s16 field1A;
  s16 field1C;
  u8 pad1E[0x24 - 0x1E];
} FireFlyLanternSpawnSetup;

STATIC_ASSERT(sizeof(FireFlyLanternSpawnSetup) == 0x24);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, x) == 0x08);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field18) == 0x18);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field19) == 0x19);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field1A) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyLanternSpawnSetup, field1C) == 0x1C);

typedef struct FireFlyLanternState {
  int fireflies[7];
  u8 fireflyCount;
  u8 remainingCount;
  u8 flags;
  u8 pad1F;
  s16 gameBit;
  u8 pad22[0x24 - 0x22];
} FireFlyLanternState;

typedef struct FireFlyLanternStateFlags {
  u8 finished : 1;
} FireFlyLanternStateFlags;

STATIC_ASSERT(sizeof(FireFlyLanternState) == 0x24);
STATIC_ASSERT(offsetof(FireFlyLanternState, fireflyCount) == 0x1C);
STATIC_ASSERT(offsetof(FireFlyLanternState, remainingCount) == 0x1D);
STATIC_ASSERT(offsetof(FireFlyLanternState, flags) == 0x1E);
STATIC_ASSERT(offsetof(FireFlyLanternState, gameBit) == 0x20);

#include "main/dll/CF/lanternfirefly_state.h"

extern ObjectDescriptor gLanternFireFlyObjDescriptor;
extern ObjectDescriptor gFireFlyLanternObjDescriptor;
extern ObjectDescriptor gFlammableVineObjDescriptor;

int LanternFireFly_getExtraSize(void);
int LanternFireFly_getObjectTypeId(void);
void LanternFireFly_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void LanternFireFly_hitDetect(void);
void LanternFireFly_update(int obj);
void LanternFireFly_init(int obj, int def);
void LanternFireFly_release(void);
void LanternFireFly_initialise(void);

int FireFlyLantern_getExtraSize(void);
int FireFlyLantern_getObjectTypeId(void);
void FireFlyLantern_free(int obj);
void FireFlyLantern_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FireFlyLantern_update(int obj);
void FireFlyLantern_init(int param_1,int param_2);
int FireFlyLantern_spawnFireFly(int *obj);
int FireFlyLantern_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);

int flammablevine_getExtraSize(void);
int flammablevine_getObjectTypeId(void);
void flammablevine_free(int obj);
void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void flammablevine_hitDetect(void);
void flammablevine_update(void);
void flammablevine_init(void);
void flammablevine_release(void);
void flammablevine_initialise(void);

#endif /* MAIN_DLL_CF_CFCRYSTAL_H_ */
