#ifndef MAIN_DLL_DLL_00D4_SKEETLAWALL_H_
#define MAIN_DLL_DLL_00D4_SKEETLAWALL_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

void SkeetlaWall_setScale(GameObject* obj, f32* outBounds, u8* outShapeFlag);
extern ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor;

#endif /* MAIN_DLL_DLL_00D4_SKEETLAWALL_H_ */
