#ifndef MAIN_DLL_DLL_0194_GPSHSCENE_H_
#define MAIN_DLL_DLL_0194_GPSHSCENE_H_

#include "main/game_object.h"

int gpsh_scene_getExtraSize(void);
int gpsh_scene_getObjectTypeId(void);
void gpsh_scene_free(void);
void gpsh_scene_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void gpsh_scene_hitDetect(void);
void gpsh_scene_update(void);
void gpsh_scene_init(int* obj, int* def);
void gpsh_scene_release(void);
void gpsh_scene_initialise(void);

#endif /* MAIN_DLL_DLL_0194_GPSHSCENE_H_ */
