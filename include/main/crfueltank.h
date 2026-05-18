#ifndef MAIN_CRFUELTANK_H_
#define MAIN_CRFUELTANK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

typedef struct CrFuelTankState {
  u8 unk0[0xc];
  u8 timer[4];
} CrFuelTankState;

typedef struct CrFuelTankDef {
  u8 unk0[0x1a];
  s16 idleFrameCount;
  u8 unk1C[2];
  s16 hitEvent;
} CrFuelTankDef;

typedef struct CrFuelTankCollider {
  u8 unk0[0x50];
  void *hitObj;
} CrFuelTankCollider;

typedef struct CrFuelTankHitObj {
  u8 unk0[0x24];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk30[0x16];
  s16 objType;
} CrFuelTankHitObj;

typedef struct CrFuelTankObject {
  u8 unk0[6];
  s16 flags;
  u8 unk8[0x1c];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 unk30[6];
  u8 fadeTimer;
  u8 unk37[0x15];
  CrFuelTankDef *def;
  u8 unk50[4];
  CrFuelTankCollider *collider;
  u8 unk58[0x60];
  CrFuelTankState *state;
  u8 unkBC[0x3c];
  int triggered;
} CrFuelTankObject;

extern ObjectDescriptor gCrFuelTankObjDescriptor;

int crfueltank_getExtraSize(void);
int crfueltank_func08(void);
void crfueltank_free(void);
void crfueltank_render(void);
void crfueltank_hitDetect(CrFuelTankObject *obj);
void crfueltank_update(CrFuelTankObject *obj);
void crfueltank_init(CrFuelTankObject *obj,CrFuelTankDef *def);
void crfueltank_release(void);
void crfueltank_initialise(void);

#endif /* MAIN_CRFUELTANK_H_ */
