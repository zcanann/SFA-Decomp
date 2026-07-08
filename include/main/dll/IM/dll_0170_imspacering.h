#ifndef MAIN_DLL_IM_DLL_0170_IMSPACERING_H_
#define MAIN_DLL_IM_DLL_0170_IMSPACERING_H_

#include "ghidra_import.h"
#include "main/game_object.h"

int IMSpaceRing_getExtraSize(void);
int IMSpaceRing_getObjectTypeId(void);
void IMSpaceRing_free(void);
void IMSpaceRing_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void IMSpaceRing_hitDetect(void);
void IMSpaceRing_update(GameObject* obj);
void IMSpaceRing_init(GameObject* obj, s8* placement);
void IMSpaceRing_release(void);
void IMSpaceRing_initialise(void);

#endif
