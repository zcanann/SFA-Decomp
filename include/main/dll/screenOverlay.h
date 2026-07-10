#ifndef MAIN_DLL_SCREENOVERLAY_H_
#define MAIN_DLL_SCREENOVERLAY_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void ProjectileSwitch_render(GameObject* obj, int p2, int p3, int p4, int p5, char flag);
void ProjectileSwitch_hitDetect(GameObject* obj);
void ProjectileSwitch_update(GameObject* obj);
void ProjectileSwitch_init(GameObject* obj, u8* initData);
void ProjectileSwitch_release(void);
void ProjectileSwitch_initialise(void);
int InvisibleHitSwitch_getExtraSize(void);
void InvisibleHitSwitch_update(GameObject* obj);

#endif /* MAIN_DLL_SCREENOVERLAY_H_ */
