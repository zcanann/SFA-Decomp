#ifndef MAIN_DLL_DFBARRELANIM_H_
#define MAIN_DLL_DFBARRELANIM_H_

#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"

DFRope* DFRope_Create(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32 unused, s32 count,
                      f32 tickScale);
void dfropenode_setMinY(int obj, float value);
int dfropenode_isVisible(int obj);
void dfropenode_setVisible(int obj, int value);
void dfropenode_clearLinkedObj(int obj);
int dfropenode_getAngle(int obj);
f32 fn_801C1698(f32* x, f32* y, f32* z, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ);

#endif /* MAIN_DLL_DFBARRELANIM_H_ */
