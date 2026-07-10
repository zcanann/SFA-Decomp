#ifndef MAIN_DLL_WC_DLL_0297_WCTEMPLEBRI_H_
#define MAIN_DLL_WC_DLL_0297_WCTEMPLEBRI_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_update.h"

void wctemplebri_updateModelWarp(int obj, int p2);
int wctemplebri_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate);
int wctemplebri_getExtraSize(void);
int wctemplebri_getObjectTypeId(GameObject* obj);
void wctemplebri_free(void);
void wctemplebri_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wctemplebri_hitDetect(void);
void wctemplebri_release(void);
void wctemplebri_initialise(void);
void wctemplebri_update(int obj);
void wctemplebri_init(int obj, int initData);

#endif /* MAIN_DLL_WC_DLL_0297_WCTEMPLEBRI_H_ */
