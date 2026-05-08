#ifndef MAIN_DLL_FRONT_POST_H_
#define MAIN_DLL_FRONT_POST_H_

#include "ghidra_import.h"

typedef struct PostObjAnimComponent PostObjAnimComponent;
typedef struct PostObject PostObject;
typedef struct PostControl PostControl;

int fn_80115650(PostObjAnimComponent *objAnim,PostObject *obj,int *turning,
                PostControl *control,float *turnSpeed,short *moves);
void fn_801159DC(void);
void fn_801159E0(void);

#endif /* MAIN_DLL_FRONT_POST_H_ */
