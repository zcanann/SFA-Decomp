#ifndef MAIN_DLL_DIM_DLL_00C7_DIM2ROOFRUB_API_H_
#define MAIN_DLL_DIM_DLL_00C7_DIM2ROOFRUB_API_H_

#include "types.h"

void dim2roofrub_free(int* obj);
int dim2roofrub_getExtraSize(void);
void dim2roofrub_init(int* obj, int* params);
void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);
void dim2roofrub_update(int* obj);

#endif /* MAIN_DLL_DIM_DLL_00C7_DIM2ROOFRUB_API_H_ */
