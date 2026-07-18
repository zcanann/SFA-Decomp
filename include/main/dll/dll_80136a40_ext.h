#ifndef MAIN_DLL_DLL_80136A40_EXT_H_
#define MAIN_DLL_DLL_80136A40_EXT_H_

#include "types.h"

void Tricky_updateBlendChannelWeight(int obj, u8* state);
void Tricky_emitQueuedPathParticles(u8* a, u8* b);
int trickySelectQueuedCommandTarget(u8* state, int commandType);

#endif /* MAIN_DLL_DLL_80136A40_EXT_H_ */
