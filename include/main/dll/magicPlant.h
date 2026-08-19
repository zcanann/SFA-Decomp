#ifndef MAIN_DLL_MAGICPLANT_H_
#define MAIN_DLL_MAGICPLANT_H_

#include "game/objects/object.h"

extern u8 gMagicPlantSeqEntryTable[8];

void vambat_init(GameObject* obj, void* state);
void vambat_updateIdle(GameObject* obj, void* state);
void vambat_updateEngaged(GameObject* obj, void* state);
void magicplantSpawnMovePuffs(GameObject* obj, void* state);

#endif /* MAIN_DLL_MAGICPLANT_H_ */
