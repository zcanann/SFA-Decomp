#ifndef MAIN_DLL_IM_DLL_016E_IMANIMSPACECRAFT_H_
#define MAIN_DLL_IM_DLL_016E_IMANIMSPACECRAFT_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

void imanimspacecraft_modelMtxFn(void);
u32 imanimspacecraft_getEventFlag(GameObject* obj);
int imanimspacecraft_setScale(GameObject* obj, int bitIdx);
int imanimspacecraft_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int imanimspacecraft_getExtraSize(void);
int imanimspacecraft_getObjectTypeId(void);
void imanimspacecraft_free(GameObject* obj);
void imanimspacecraft_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void imanimspacecraft_hitDetect(void);
void imanimspacecraft_update(GameObject* obj);
void imanimspacecraft_init(GameObject* obj);
void imanimspacecraft_release(void);
void imanimspacecraft_initialise(void);

extern ObjectDescriptor13 gIMAnimSpaceCraftObjDescriptor;

#endif
