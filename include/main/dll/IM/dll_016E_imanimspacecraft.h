#ifndef MAIN_DLL_IM_DLL_016E_IMANIMSPACECRAFT_H_
#define MAIN_DLL_IM_DLL_016E_IMANIMSPACECRAFT_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

void imanimspacecraft_modelMtxFn(void);
u32 imanimspacecraft_func0B(int* obj);
int imanimspacecraft_setScale(int* obj, int bitIdx);
int imanimspacecraft_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int imanimspacecraft_getExtraSize(void);
int imanimspacecraft_getObjectTypeId(void);
void imanimspacecraft_free(GameObject* obj);
void imanimspacecraft_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void imanimspacecraft_hitDetect(void);
void imanimspacecraft_update(GameObject* obj);
void imanimspacecraft_init(GameObject* obj);
void imanimspacecraft_release(void);
void imanimspacecraft_initialise(void);

#endif
