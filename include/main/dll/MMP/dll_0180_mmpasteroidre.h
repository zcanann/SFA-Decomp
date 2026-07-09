#ifndef MAIN_DLL_MMP_DLL_0180_MMPASTEROIDRE_H_
#define MAIN_DLL_MMP_DLL_0180_MMPASTEROIDRE_H_

#include "main/objanim_update.h"

void mmp_asteroid_re_free(void);
void mmp_asteroid_re_hitDetect(void);
void mmp_asteroid_re_release(void);
void mmp_asteroid_re_initialise(void);
int mmp_asteroid_re_getExtraSize(void);
int mmp_asteroid_re_getObjectTypeId(void);
void mmp_asteroid_re_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
int mmp_asteroid_re_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
void mmp_asteroid_re_init(struct GameObject *obj);
void mmp_asteroid_re_update(int obj);

#endif /* MAIN_DLL_MMP_DLL_0180_MMPASTEROIDRE_H_ */
