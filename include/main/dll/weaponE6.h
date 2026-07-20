#ifndef MAIN_DLL_WEAPONE6_H_
#define MAIN_DLL_WEAPONE6_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void tricky_fetchBall(GameObject* obj, int state);
void tricky_idleAndEat(GameObject* obj, int state);
void tricky_trackTumbleweed(GameObject* obj, int state);
void tricky_moveToFollowTarget(int obj, int state);

#endif /* MAIN_DLL_WEAPONE6_H_ */
