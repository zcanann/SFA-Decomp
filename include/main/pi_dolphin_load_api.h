#ifndef MAIN_PI_DOLPHIN_LOAD_API_H_
#define MAIN_PI_DOLPHIN_LOAD_API_H_

#include "types.h"

int fileLoadToBuffer(int id, void* buffer);
void viFn_8004a56c(int val);
void tex0GetFrame(int texId, int unused, int* outA, int* outB, int count, u8* frameTable, int queryMode);

#endif /* MAIN_PI_DOLPHIN_LOAD_API_H_ */
