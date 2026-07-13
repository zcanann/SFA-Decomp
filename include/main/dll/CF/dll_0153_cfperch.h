#ifndef MAIN_DLL_CF_DLL_0153_CFPERCH_H_
#define MAIN_DLL_CF_DLL_0153_CFPERCH_H_

#include "types.h"
#include "main/objanim_update.h"

int CFPerch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int cfperch_getExtraSize(void);
int cfperch_getObjectTypeId(void);
void cfperch_free(int* obj);
void cfperch_render(void);
void cfperch_hitDetect(void);
void cfperch_update(int* obj);
void cfperch_init(int* obj);
void cfperch_release(void);
void cfperch_initialise(void);

#endif /* MAIN_DLL_CF_DLL_0153_CFPERCH_H_ */
