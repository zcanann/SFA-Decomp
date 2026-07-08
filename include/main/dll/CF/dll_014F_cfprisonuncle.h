#ifndef MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_
#define MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_

#include "main/objanim_update.h"

int CFPrisonUncle_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int cfprisonuncle_getExtraSize(void);
int cfprisonuncle_getObjectTypeId(void);
void cfprisonuncle_free(void);
void cfprisonuncle_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void cfprisonuncle_hitDetect(void);
void cfprisonuncle_update(int* obj);
void cfprisonuncle_init(int* obj);
void cfprisonuncle_release(void);
void cfprisonuncle_initialise(void);

#endif /* MAIN_DLL_CF_DLL_014F_CFPRISONUNCLE_H_ */
