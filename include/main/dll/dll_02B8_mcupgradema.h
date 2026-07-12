#ifndef MAIN_DLL_DLL_02B8_MCUPGRADEMA_H
#define MAIN_DLL_DLL_02B8_MCUPGRADEMA_H

#include "main/dll/mcupgrade_state.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gMCUpgradeMaObjDescriptor;

int mcupgradema_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void mcupgradema_update(GameObject* obj);
void mcupgradema_init(GameObject* obj);

#endif
