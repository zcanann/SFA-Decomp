#ifndef MAIN_DLL_DLL_0240_GCROBOTBLAST_H_
#define MAIN_DLL_DLL_0240_GCROBOTBLAST_H_

#include "global.h"
#include "main/objanim_update.h"

int GCRobotBlast_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int GCRobotBlast_getExtraSize(void);
int GCRobotBlast_getObjectTypeId(void);
void GCRobotBlast_free(void);
void GCRobotBlast_render(void);
void GCRobotBlast_hitDetect(void);
void GCRobotBlast_update(void);
void GCRobotBlast_init(struct GameObject *obj, s8* def);
void GCRobotBlast_release(void);
void GCRobotBlast_initialise(void);

#endif /* MAIN_DLL_DLL_0240_GCROBOTBLAST_H_ */
