#ifndef MAIN_DLL_CC_DLL_018B_CCLEVCONTROL_H_
#define MAIN_DLL_CC_DLL_018B_CCLEVCONTROL_H_

#include "global.h"
#include "main/objanim_update.h"

int cclevcontrol_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int cclevcontrol_getExtraSize(void);
void cclevcontrol_free(void);
void cclevcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void cclevcontrol_update(int obj);
void cclevcontrol_init(int* obj);

#endif /* MAIN_DLL_CC_DLL_018B_CCLEVCONTROL_H_ */
