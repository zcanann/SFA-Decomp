#ifndef MAIN_DLL_CC_DLL_0188_CCLIGHTFOOT_H_
#define MAIN_DLL_CC_DLL_0188_CCLIGHTFOOT_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

int cclightfoot_getExtraSize(void);
void cclightfoot_init(int* obj, int* placement);
void cclightfoot_free(int* obj, int flag);
int CClightfoot_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void cclightfoot_update(int obj);

#endif /* MAIN_DLL_CC_DLL_0188_CCLIGHTFOOT_H_ */
