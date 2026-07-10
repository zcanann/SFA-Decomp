#ifndef MAIN_OBJTEXTURE_H_
#define MAIN_OBJTEXTURE_H_

#include "main/objanim_internal.h"
#include "main/game_object.h"

ObjTextureRuntimeSlot* objFindTexture(GameObject* obj, int target, int unusedMaterialIndex);

#endif /* MAIN_OBJTEXTURE_H_ */
