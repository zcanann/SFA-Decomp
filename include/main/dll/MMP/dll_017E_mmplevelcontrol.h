#ifndef MAIN_DLL_MMP_DLL_017E_MMPLEVELCONTROL_H_
#define MAIN_DLL_MMP_DLL_017E_MMPLEVELCONTROL_H_

#include "main/objanim_update.h"

int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int MMP_levelcontrol_getExtraSize(void);
int MMP_levelcontrol_getObjectTypeId(void);
void MMP_levelcontrol_free(int obj);
void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MMP_levelcontrol_hitDetect(void);
void MMP_levelcontrol_update(int obj);
void MMP_levelcontrol_init(struct GameObject* obj);
void MMP_levelcontrol_release(void);
void MMP_levelcontrol_initialise(void);

#endif /* MAIN_DLL_MMP_DLL_017E_MMPLEVELCONTROL_H_ */
