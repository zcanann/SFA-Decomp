#ifndef MAIN_PI_DOLPHIN_FILELOAD_API_H_
#define MAIN_PI_DOLPHIN_FILELOAD_API_H_

#include "types.h"

int fileLoadToBuffer(int id, void* buffer);
int initLoadFiles(void);
void viFn_8004a56c(int val);
void fn_8004C234(f32* p1, f32* p2);
void checkLoadBlock(int a, int* pc, int* p8);

#endif /* MAIN_PI_DOLPHIN_FILELOAD_API_H_ */
