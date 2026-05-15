#ifndef MAIN_DLL_DF_DFBARRELANIM_H_
#define MAIN_DLL_DF_DFBARRELANIM_H_

#include "ghidra_import.h"

void *fn_801C1238(s32 count, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ,
                  f32 unused, f32 tickScale);
void dfropenode_func12(int obj,float value);
int dfropenode_func11(int obj);
void dfropenode_func10(int obj,int value);
void dfropenode_func13(int obj);
int dfropenode_func0F(int obj);
f32 fn_801C1698(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32 *x, f32 *y,
                f32 *z);

#endif /* MAIN_DLL_DF_DFBARRELANIM_H_ */
