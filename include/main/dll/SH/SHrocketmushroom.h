#ifndef MAIN_DLL_SH_SHROCKETMUSHROOM_H_
#define MAIN_DLL_SH_SHROCKETMUSHROOM_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct BombPlantingSpotMapData {
  ObjPlacement base;
  s8 yawByte;
  u8 pad19[0x1E - 0x19];
  s16 plantedGameBit;
  s16 requiredGameBit;
} BombPlantingSpotMapData;

typedef struct BombPlantSporeState {
  /* 0x000 */ u16 damageType;
  /* 0x002 */ u8 pad02[0x08 - 0x02];
  /* 0x008 */ u8 pathState[0x270 - 0x08];
  /* 0x270 */ void *light;
  /* 0x274 */ f32 fuseTimer;
  /* 0x278 */ f32 driftAmplitude; /* lerps toward randomPhase; scales driftBaseX/Z */
  /* 0x27C */ f32 driftSpeed;
  /* 0x280 */ f32 randomPhase;
  /* 0x284 */ f32 driftTimer;
  /* 0x288 */ f32 driftBaseX;
  /* 0x28C */ f32 driftBaseZ;
  /* 0x290 */ f32 driftSin;
  /* 0x294 */ f32 driftCos;
  /* 0x298 */ f32 spinTimer;
  /* 0x29C */ f32 driftSpeedTarget;
  /* 0x2A0 */ f32 spinChangeTimer;
  /* 0x2A4 */ f32 detonateTimer;
  /* 0x2A8 */ s16 currentSpinAngle; /* smoothed angle chasing spinAngle; drives drift sin/cos */
  /* 0x2AA */ s16 burstDriftAngle; /* burst drift heading clamped to baseAngle +/- angleSpread */
  /* 0x2AC */ s16 spinAngle;
  /* 0x2AE */ s16 yawStep;
  /* 0x2B0 */ u8 stateFlags;
} BombPlantSporeState;

STATIC_ASSERT(offsetof(BombPlantSporeState, pathState) == 0x08);
STATIC_ASSERT(offsetof(BombPlantSporeState, light) == 0x270);
STATIC_ASSERT(offsetof(BombPlantSporeState, fuseTimer) == 0x274);
STATIC_ASSERT(offsetof(BombPlantSporeState, randomPhase) == 0x280);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftSpeedTarget) == 0x29C);
STATIC_ASSERT(offsetof(BombPlantSporeState, detonateTimer) == 0x2A4);
STATIC_ASSERT(offsetof(BombPlantSporeState, spinAngle) == 0x2AC);
STATIC_ASSERT(offsetof(BombPlantSporeState, yawStep) == 0x2AE);
STATIC_ASSERT(offsetof(BombPlantSporeState, stateFlags) == 0x2B0);
STATIC_ASSERT(offsetof(BombPlantingSpotMapData, yawByte) == 0x18);
STATIC_ASSERT(offsetof(BombPlantingSpotMapData, plantedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BombPlantingSpotMapData, requiredGameBit) == 0x20);

void bombplantingspot_init(void *obj, BombPlantingSpotMapData *mapData);
void bombplantingspot_update(void *obj);
void bombplantspore_update(void *obj);
void bombplantspore_init(void *obj, void *param2);
int sh_queenearthwalker_processAnimEvents(void *obj, void *unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_SH_SHROCKETMUSHROOM_H_ */
