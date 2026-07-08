#ifndef MAIN_DLL_DLL_0150_GCROBOTLIGHTBEA_H_
#define MAIN_DLL_DLL_0150_GCROBOTLIGHTBEA_H_

#include "types.h"

u32 fn_801A0174(int* obj);
int gcrobotlightbea_getExtraSize(void);
int gcrobotlightbea_getObjectTypeId(void);
void gcrobotlightbea_free(int* obj);
void gcrobotlightbea_render(void);
void gcrobotlightbea_hitDetect(int obj);
void gcrobotlightbea_update(int* obj);
void gcrobotlightbea_init(int* obj);
void gcrobotlightbea_release(void);
void gcrobotlightbea_initialise(void);

#endif /* MAIN_DLL_DLL_0150_GCROBOTLIGHTBEA_H_ */
