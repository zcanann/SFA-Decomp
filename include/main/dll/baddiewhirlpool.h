#ifndef MAIN_DLL_BADDIEWHIRLPOOL_H_
#define MAIN_DLL_BADDIEWHIRLPOOL_H_

#include "dlls/objects/201_Baddie.h"

typedef struct GameObject GameObject;

void iceBaddie_enterWhirlpoolGroup(GameObject* obj, EnemyState* state);
void iceBaddie_leaveWhirlpoolGroup(GameObject* obj, EnemyState* state);
void baddie_initWhirlpoolState(int* obj, EnemyState* state);

#endif /* MAIN_DLL_BADDIEWHIRLPOOL_H_ */
