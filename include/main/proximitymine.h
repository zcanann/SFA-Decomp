#ifndef MAIN_PROXIMITYMINE_H_
#define MAIN_PROXIMITYMINE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

/* Runtime state of a proximity mine (ProximityMineState.mode). */
typedef enum ProximityMineMode {
  PROXIMITYMINE_MODE_LAUNCHING = -1, /* compute launch velocity then fall through to flight */
  PROXIMITYMINE_MODE_EXPIRED = 0,    /* stopped/destroyed: count render timer then free */
  PROXIMITYMINE_MODE_FLIGHT = 1,     /* integrate launch velocity, then fall through to armed */
  PROXIMITYMINE_MODE_ARMED = 2,      /* live: spawn fx, enable hit detection */
  PROXIMITYMINE_MODE_WAITING = 3     /* idle until player enters trigger range, then arm */
} ProximityMineMode;

/* Placement-config spawn variant (ProximityMineDef.mode). */
typedef enum ProximityMineSpawnMode {
  PROXIMITYMINE_SPAWN_TIMED = 0,     /* stationary mine armed after a parameter delay */
  PROXIMITYMINE_SPAWN_LAUNCHED = 1,  /* launched/thrown mine */
  PROXIMITYMINE_SPAWN_PROXIMITY = 2  /* immediately-armed proximity mine */
} ProximityMineSpawnMode;

typedef struct ProximityMineEffect {
  u8 unk0[0x4c];
  u8 visible;
  u8 unk4D[0x2f8 - 0x4d];
  u8 active;
} ProximityMineEffect;

typedef struct ProximityMineState {
  void *targetObj;
  ProximityMineEffect *effectHandle;
  f32 triggerDistance;
  f32 verticalStep;
  u8 unk10[4];
  f32 renderTimer;
  f32 launchTimer;
  f32 resetTimer;
  f32 bounceTimer;
  f32 initTimer;
  f32 lifespanTimer;
  s8 mode;
  u8 unk2D;
  u8 flashMode;
  u8 unk2F;
  u8 effectVisible;
  u8 unk31[3];
} ProximityMineState;

typedef struct ProximityMineCollider {
  u8 unk0[0x50];
  void *hitObj;
  u8 unk54[0x59];
  s8 hitFlag;
} ProximityMineCollider;

typedef struct ProximityMineObject {
  s16 angle;
  s16 angle2;
  u8 unk04[4];
  f32 height;
  f32 posX;
  f32 posY;
  f32 posZ;
  f32 prevX;
  f32 prevY;
  f32 prevZ;
  f32 velocityX;
  f32 velocityY;
  f32 velocityZ;
  u8 unk30[0x16];
  s16 objId;
  u8 unk48[4];
  struct ProximityMineDef *def;
  u8 unk50[4];
  ProximityMineCollider *collider;
  u8 unk58[0x50];
  f32 lightPosY; /* 0xA8: Y position of the proximity-mine glow point light */
  u8 unkAC[0xc];
  ProximityMineState *state;
  u8 unkBC[8];
  void *pendingTarget;
  u8 unkC8[0x2c];
  int pathIndex;
} ProximityMineObject;

typedef struct ProximityMineDef {
  u8 unk0[0x18];
  s8 angleSeed;
  s8 mode;
  s16 parameter;
} ProximityMineDef;

extern ObjectDescriptor gProximityMineObjDescriptor;

void proximitymine_resetToIdle(ProximityMineObject *obj);
int proximitymine_getExtraSize(void);
int proximitymine_getObjectTypeId(void);
void proximitymine_free(ProximityMineObject *obj);
void proximitymine_render(ProximityMineObject *obj,u32 param_2,u32 param_3,
                          u32 param_4,u32 param_5);
void proximitymine_hitDetect(ProximityMineObject *obj);
void proximitymine_update(ProximityMineObject *obj);
void proximitymine_init(ProximityMineObject *obj,ProximityMineDef *def);
void proximitymine_release(void);
void proximitymine_initialise(void);

#endif /* MAIN_PROXIMITYMINE_H_ */
