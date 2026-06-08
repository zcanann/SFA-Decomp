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
  u8 pad00[0x08];
  u8 pathState[0x270 - 0x08];
  void *light;
  f32 fuseTimer;
  u8 pad278[0x280 - 0x278];
  f32 randomPhase;
  u8 pad284[0x2AC - 0x284];
  s16 spinAngle;
  s16 yawStep;
  u8 stateFlags;
} BombPlantSporeState;

STATIC_ASSERT(offsetof(BombPlantSporeState, pathState) == 0x08);
STATIC_ASSERT(offsetof(BombPlantSporeState, light) == 0x270);
STATIC_ASSERT(offsetof(BombPlantSporeState, fuseTimer) == 0x274);
STATIC_ASSERT(offsetof(BombPlantSporeState, randomPhase) == 0x280);
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
