#ifndef MAIN_DLL_DLL_01FC_LASERBEAM_H_
#define MAIN_DLL_DLL_01FC_LASERBEAM_H_

#include "types.h"

int LaserBeam_getExtraSize(void);
int LaserBeam_getObjectTypeId(void);
void LaserBeam_free(int* obj);
void LaserBeam_render(void);
void LaserBeam_hitDetect(void);
void LaserBeam_update(int obj);
void LaserBeam_init(s16* obj, char* arg);
void LaserBeam_release(void);
void LaserBeam_initialise(void);

#endif /* MAIN_DLL_DLL_01FC_LASERBEAM_H_ */
