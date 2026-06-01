#ifndef MAIN_DLL_LGT_LGTDIRECTIONALLIGHT_H_
#define MAIN_DLL_LGT_LGTDIRECTIONALLIGHT_H_

#include "ghidra_import.h"

void wmworm_update(short *obj);
void wmworm_init(s16 *obj, s8 *def);
void wmworm_release(void);
void wmworm_initialise(void);

int wmlevelcontrol_getExtraSize(void);
int wmlevelcontrol_getObjectTypeId(void);
void wmlevelcontrol_free(int obj);
void wmlevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wmlevelcontrol_hitDetect(void);

#endif /* MAIN_DLL_LGT_LGTDIRECTIONALLIGHT_H_ */
