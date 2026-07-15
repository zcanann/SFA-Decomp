#ifndef MAIN_DLL_SC_DLL_01B9_SCCLOUDRUNNERA_H_
#define MAIN_DLL_SC_DLL_01B9_SCCLOUDRUNNERA_H_

#include "main/game_object.h"

int sc_cloudrunnera_getExtraSize(void);
int sc_cloudrunnera_getObjectTypeId(void);
void sc_cloudrunnera_free(int* obj);
void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void sc_cloudrunnera_hitDetect(void);
void sc_cloudrunnera_update(int obj);
void sc_cloudrunnera_init(GameObject* obj, int def);
void sc_cloudrunnera_release(void);
void sc_cloudrunnera_initialise(void);

#endif /* MAIN_DLL_SC_DLL_01B9_SCCLOUDRUNNERA_H_ */
