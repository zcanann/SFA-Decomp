#ifndef MAIN_DLL_DLL_00F8_LEVELNAME_H_
#define MAIN_DLL_DLL_00F8_LEVELNAME_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

int LevelName_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int LevelName_getExtraSize(void);
int LevelName_getObjectTypeId(void);
void LevelName_free(void);
void LevelName_render(void);
void LevelName_hitDetect(void);
void LevelName_update(GameObject* obj);
void LevelName_init(GameObject* obj, int objDef);
void LevelName_release(void);
void LevelName_initialise(void);

#endif /* MAIN_DLL_DLL_00F8_LEVELNAME_H_ */
