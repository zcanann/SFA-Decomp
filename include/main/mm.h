#ifndef MAIN_MM_H_
#define MAIN_MM_H_

#include "ghidra_import.h"

int roundUpTo4(int value);
int roundUpTo8(int value);
void mm_free(void *ptr);
void *mmAlloc(int size, int type, int flag);

#endif /* MAIN_MM_H_ */
