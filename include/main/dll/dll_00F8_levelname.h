#ifndef MAIN_DLL_DLL_00F8_LEVELNAME_H_
#define MAIN_DLL_DLL_00F8_LEVELNAME_H_

#include "main/objanim_update.h"

int LevelName_SeqFn(struct GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int LevelName_getExtraSize(void);
int LevelName_getObjectTypeId(void);
void LevelName_free(void);
void LevelName_render(void);
void LevelName_hitDetect(void);
void LevelName_update(int* obj);
void LevelName_init(struct GameObject* obj, int objDef);
void LevelName_release(void);
void LevelName_initialise(void);

#endif /* MAIN_DLL_DLL_00F8_LEVELNAME_H_ */
