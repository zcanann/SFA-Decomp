#ifndef MAIN_DLL_CF_DLL_0154_CFPRISONCAGE_H_
#define MAIN_DLL_CF_DLL_0154_CFPRISONCAGE_H_

#include "types.h"
#include "main/objanim_update.h"

int CFPrisonCage_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int CFPrisonCage_getExtraSize(void);
int CFPrisonCage_getObjectTypeId(int* obj);
void CFPrisonCage_free(void);
void CFPrisonCage_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void CFPrisonCage_hitDetect(int* obj);
void CFPrisonCage_update(int* obj);
void CFPrisonCage_init(int* obj, u8* def);
void CFPrisonCage_release(void);
void CFPrisonCage_initialise(void);

#endif /* MAIN_DLL_CF_DLL_0154_CFPRISONCAGE_H_ */
