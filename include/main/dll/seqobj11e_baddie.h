#ifndef H_MAIN_DLL_SEQOBJ11E_BADDIE_H
#define H_MAIN_DLL_SEQOBJ11E_BADDIE_H

#include "game/objects/object.h"

void guardClaw_update(GameObject* obj, u8* state);
void gcRobotPatrol_update(GameObject* obj, u8* state);
void guardClaw_init(GameObject* obj, u8* state);
void gcRobotPatrol_init(GameObject* obj, void* state);

#endif /* H_MAIN_DLL_SEQOBJ11E_BADDIE_H */
