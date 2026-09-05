#ifndef MAIN_DLL_SKEETLA_ANIM_API_H_
#define MAIN_DLL_SKEETLA_ANIM_API_H_

#include "types.h"
#include "game/objects/object_fwd.h"

int trickyRequestMove(GameObject* obj, int newMoveId, f32 animRate, u32 flags);

#endif /* MAIN_DLL_SKEETLA_ANIM_API_H_ */
