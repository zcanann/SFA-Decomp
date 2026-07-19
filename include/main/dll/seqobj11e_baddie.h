#ifndef H_MAIN_DLL_SEQOBJ11E_BADDIE_H
#define H_MAIN_DLL_SEQOBJ11E_BADDIE_H

#include "main/game_object.h"

void guardClaw_update(int* obj, u8* state);
void gcRobotPatrol_update(int* obj, u8* state);
void guardClaw_init(int* obj, u8* state);
void gcRobotPatrol_init(GameObject* obj, int state);

#endif /* H_MAIN_DLL_SEQOBJ11E_BADDIE_H */
