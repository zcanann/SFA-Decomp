#ifndef MAIN_SHADER_MAP_TEXT_API_H_
#define MAIN_SHADER_MAP_TEXT_API_H_

#include "types.h"

#ifdef SHADER_MAP_TEXT_DIRECT_INT_CALL
void gameTextLoadForMap_800571f0(int force);
#else
void gameTextLoadForMap_800571f0(u8 force);
#endif

#endif /* MAIN_SHADER_MAP_TEXT_API_H_ */
