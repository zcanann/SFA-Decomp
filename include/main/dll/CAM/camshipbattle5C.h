#ifndef MAIN_DLL_CAM_CAMSHIPBATTLE5C_H_
#define MAIN_DLL_CAM_CAMSHIPBATTLE5C_H_

#include "ghidra_import.h"

void pathcam_buildWindowSamples(int *nodes, f32 *o1, f32 *o2, f32 *o3, f32 *o4,
                                f32 *o5, f32 *o6, f32 *o7);
void pathcam_findTaggedNodeWindow(u8 *node, int *out, int tag);

#endif /* MAIN_DLL_CAM_CAMSHIPBATTLE5C_H_ */
