#ifndef MAIN_DLL_SCREENOVERLAY_H_
#define MAIN_DLL_SCREENOVERLAY_H_

#include "ghidra_import.h"

void ProjectileSwitch_render(int obj, int p2, int p3, int p4, int p5, char flag);
void ProjectileSwitch_hitDetect(int obj);
void ProjectileSwitch_update(int obj);
void ProjectileSwitch_init(int obj, u8 *initData);
void ProjectileSwitch_release(void);
void ProjectileSwitch_initialise(void);
int InvisibleHitSwitch_getExtraSize(void);
void InvisibleHitSwitch_update(int obj);

#endif /* MAIN_DLL_SCREENOVERLAY_H_ */
