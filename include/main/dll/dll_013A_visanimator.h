#ifndef MAIN_DLL_DLL_013A_VISANIMATOR_H_
#define MAIN_DLL_DLL_013A_VISANIMATOR_H_

#include "global.h"

int VisAnimator_getExtraSize(void);
int VisAnimator_getObjectTypeId(void);
void VisAnimator_free(void);
void VisAnimator_render(void);
void VisAnimator_hitDetect(void);
void VisAnimator_update(int* obj);
void VisAnimator_init(int* obj, int* desc);
void VisAnimator_release(void);
void VisAnimator_initialise(void);

#endif /* MAIN_DLL_DLL_013A_VISANIMATOR_H_ */
