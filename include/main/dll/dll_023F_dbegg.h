#ifndef MAIN_DLL_DLL_023F_DBEGG_H_
#define MAIN_DLL_DLL_023F_DBEGG_H_

#include "main/game_object.h"

int dbegg_setLaunchVelocity(GameObject* obj, f32* velocity);
int dbegg_setScale(GameObject* obj);
int dbegg_getExtraSize(void);
int dbegg_getObjectTypeId(void);
void dbegg_free(int obj);
void dbegg_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void dbegg_hitDetect(GameObject* obj);
void dbegg_update(GameObject* obj);
void dbegg_init(GameObject* obj);
void dbegg_release(void);
void dbegg_initialise(void);

void dbegg_setupFromDef(GameObject* obj, u8* state);

#endif /* MAIN_DLL_DLL_023F_DBEGG_H_ */
