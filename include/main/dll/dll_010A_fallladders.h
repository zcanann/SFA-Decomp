#ifndef MAIN_DLL_DLL_010A_FALLLADDERS_H_
#define MAIN_DLL_DLL_010A_FALLLADDERS_H_

#include "main/game_object.h"

typedef struct FallLaddersObjectDef FallLaddersObjectDef;

int Fall_Ladders_getExtraSize(void);
int Fall_Ladders_getObjectTypeId(void);
void Fall_Ladders_free(int obj);
void Fall_Ladders_render(void);
void Fall_Ladders_hitDetect(void);
void Fall_Ladders_update(GameObject* obj);
void Fall_Ladders_init(int* obj, FallLaddersObjectDef* def);
void Fall_Ladders_release(void);
void Fall_Ladders_initialise(void);

#endif /* MAIN_DLL_DLL_010A_FALLLADDERS_H_ */
