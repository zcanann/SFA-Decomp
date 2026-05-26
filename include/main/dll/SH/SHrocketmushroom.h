#ifndef MAIN_DLL_SH_SHROCKETMUSHROOM_H_
#define MAIN_DLL_SH_SHROCKETMUSHROOM_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

typedef struct BombPlantingSpotMapData {
  u8 pad00[0x18];
  s8 yawByte;
  u8 pad19[0x1E - 0x19];
  s16 plantedGameBit;
  s16 requiredGameBit;
} BombPlantingSpotMapData;

void bombplantingspot_init(void *obj, BombPlantingSpotMapData *mapData);
void bombplantingspot_update(void *obj);
void bombplantspore_update(void *obj);
void bombplantspore_init(void *obj, void *param2);
int sh_queenearthwalker_processAnimEvents(void *obj, void *unused, ObjAnimUpdateState *animUpdate);

#endif /* MAIN_DLL_SH_SHROCKETMUSHROOM_H_ */
