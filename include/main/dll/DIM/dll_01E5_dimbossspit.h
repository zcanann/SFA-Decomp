#ifndef MAIN_DLL_DIM_DLL_01E5_DIMBOSSSPIT_H_
#define MAIN_DLL_DIM_DLL_01E5_DIMBOSSSPIT_H_

#include "main/game_object.h"
#include "types.h"

void DIMbossspit_updateBurst(GameObject* obj);
int DIMbossspit_getExtraSize(void);
int DIMbossspit_getObjectTypeId(void);
void DIMbossspit_free(int obj);
void DIMbossspit_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void DIMbossspit_hitDetect(void);
void DIMbossspit_update(GameObject* obj);
void DIMbossspit_init(int obj);
void DIMbossspit_release(void);
void DIMbossspit_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01E5_DIMBOSSSPIT_H_ */
