#ifndef DLLS_OBJECTS_608_PROXIMITYMINE_H_
#define DLLS_OBJECTS_608_PROXIMITYMINE_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/model_light.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

/* OBJINDEX object ID for this DLL's dynamically spawned CRDropBomb variant. */
#define PROXIMITYMINE_CR_DROP_BOMB_OBJ 0x5ff

/* Runtime state of a proximity mine (ProximityMineState.mode). */
typedef enum ProximityMineMode {
  PROXIMITYMINE_MODE_LAUNCHING = -1, /* compute launch velocity then fall through to flight */
  PROXIMITYMINE_MODE_EXPIRED = 0,    /* stopped/destroyed: count destruction timer then free */
  PROXIMITYMINE_MODE_FLIGHT = 1,     /* integrate launch velocity, then fall through to armed */
  PROXIMITYMINE_MODE_ARMED = 2,      /* live: spawn fx, enable hit detection */
  PROXIMITYMINE_MODE_WAITING = 3     /* idle until player enters trigger range, then arm */
} ProximityMineMode;

/* Placement-config spawn variant (ProximityMinePlacement.mode). */
typedef enum ProximityMineSpawnMode {
  PROXIMITYMINE_SPAWN_TIMED = 0,     /* grow, then count down the placement detonation delay */
  PROXIMITYMINE_SPAWN_LAUNCHED = 1,  /* launched/thrown mine */
  PROXIMITYMINE_SPAWN_PROXIMITY = 2  /* wait for the player, then count down a 120-frame fuse */
} ProximityMineSpawnMode;

/* ProximityMine_getExtraSize returns 0x34 in retail EN. */
typedef struct ProximityMineState {
  GameObject *attachmentObj;
  ModelLightStruct *glowLight;
  f32 explosionRadius; /* capsule radius on detonation; also scales explosion visuals */
  f32 growthScaleStep;
  u8 unk10[4];
  f32 destructionTimer; /* suppress rendering and contacts until the object is freed */
  f32 flightTimer;
  f32 detonationTimer;
  f32 hitEnableTimer;
  f32 unkTimer24; /* initialized to five; no reader recovered */
  f32 growthTimer; /* grow and follow attachmentObj before arming or launching */
  s8 mode;
  u8 unk2D;
  u8 unk2E; /* initialized to zero; no reader recovered */
  u8 unk2F;
  u8 previousGlowEnabled;
  u8 unk31[3];
} ProximityMineState;

STATIC_ASSERT(offsetof(ProximityMineState, attachmentObj) == 0x0);
STATIC_ASSERT(offsetof(ProximityMineState, glowLight) == 0x4);
STATIC_ASSERT(offsetof(ProximityMineState, explosionRadius) == 0x8);
STATIC_ASSERT(offsetof(ProximityMineState, growthScaleStep) == 0xC);
STATIC_ASSERT(offsetof(ProximityMineState, destructionTimer) == 0x14);
STATIC_ASSERT(offsetof(ProximityMineState, flightTimer) == 0x18);
STATIC_ASSERT(offsetof(ProximityMineState, detonationTimer) == 0x1C);
STATIC_ASSERT(offsetof(ProximityMineState, hitEnableTimer) == 0x20);
STATIC_ASSERT(offsetof(ProximityMineState, unkTimer24) == 0x24);
STATIC_ASSERT(offsetof(ProximityMineState, growthTimer) == 0x28);
STATIC_ASSERT(offsetof(ProximityMineState, mode) == 0x2C);
STATIC_ASSERT(offsetof(ProximityMineState, unk2E) == 0x2E);
STATIC_ASSERT(offsetof(ProximityMineState, previousGlowEnabled) == 0x30);
STATIC_ASSERT(sizeof(ProximityMineState) == 0x34);

/* snowclaw_spawnDropBomb allocates 0x24 bytes for this DLL's CRDropBomb variant. */
typedef struct ProximityMinePlacement {
  ObjPlacement base;
  s8 rotationHighByte;
  s8 mode;
  union {
    s16 detonationDelay;
    s16 launchRotation;
    s16 proximityDistance;
  } parameter;
  u8 unk1C[8];
} ProximityMinePlacement;

STATIC_ASSERT(offsetof(ProximityMinePlacement, rotationHighByte) == 0x18);
STATIC_ASSERT(offsetof(ProximityMinePlacement, base) == 0);
STATIC_ASSERT(offsetof(ProximityMinePlacement, mode) == 0x19);
STATIC_ASSERT(offsetof(ProximityMinePlacement, parameter.detonationDelay) == 0x1A);
STATIC_ASSERT(offsetof(ProximityMinePlacement, parameter.launchRotation) == 0x1A);
STATIC_ASSERT(offsetof(ProximityMinePlacement, parameter.proximityDistance) == 0x1A);
STATIC_ASSERT(sizeof(ProximityMinePlacement) == 0x24);

extern ObjectDescriptor gProximityMineObjDescriptor;

void ProximityMine_expire(GameObject *obj);
int ProximityMine_getExtraSize(void);
int ProximityMine_getObjectTypeId(void);
void ProximityMine_free(GameObject *obj);
void ProximityMine_render(GameObject *obj,u32 p2,u32 p3,
                          u32 p4,u32 p5);
void ProximityMine_hitDetect(GameObject *obj);
void ProximityMine_update(GameObject *obj);
void ProximityMine_init(GameObject *obj,ProximityMinePlacement *def);
void ProximityMine_release(void);
void ProximityMine_initialise(void);

#endif /* DLLS_OBJECTS_608_PROXIMITYMINE_H_ */
