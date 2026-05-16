#ifndef MAIN_DLL_BADDIE_CHUKA_H_
#define MAIN_DLL_BADDIE_CHUKA_H_

#include "ghidra_import.h"

void chuka_init(int obj, int params);
void dfpfloorbar_free(int *obj);
void chuka_release(void);
void chuka_initialise(void);
int dfpfloorbar_func08(void);
int dfpfloorbar_getExtraSize(void);
void dfpfloorbar_render(int p1, int p2, int p3, int p4, int p5, s8 p6);
void dfpfloorbar_hitDetect(int *obj);

#endif /* MAIN_DLL_BADDIE_CHUKA_H_ */
