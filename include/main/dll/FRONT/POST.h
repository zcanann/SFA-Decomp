#ifndef MAIN_DLL_FRONT_POST_H_
#define MAIN_DLL_FRONT_POST_H_

#include "ghidra_import.h"

typedef struct PostObjAnimComponent PostObjAnimComponent;
typedef struct PostObject PostObject;
typedef struct PostControl PostControl;

int objAnimFn_80115650(PostObjAnimComponent *objAnim,PostObject *obj,int *turning,
                PostControl *control,float *turnSpeed,short *moves);
void dll_2E_release_nop(void);
void dll_2E_initialise_nop(void);

#endif /* MAIN_DLL_FRONT_POST_H_ */
