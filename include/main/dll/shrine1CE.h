#ifndef MAIN_DLL_SHRINE1CE_H_
#define MAIN_DLL_SHRINE1CE_H_

#include "ghidra_import.h"

void dll_19B_update(void);
int dll_19E_getExtraSize(void);
int dll_19E_getObjectTypeId(void);
void dll_19B_init(u8 *obj, u8 *params);
void dll_19B_release(void);
void dll_19B_initialise(void);
int dll_19C_getExtraSize(void);
int dll_19C_getObjectTypeId(void);
void dll_19C_free(void);
void dll_19C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_19C_hitDetect(void);
void dll_19C_update(int *obj);
void dll_19C_init(int obj, u8 *initData);
void dll_19C_release(void);
void dll_19C_initialise(void);
int dll_19D_getExtraSize(void);
int dll_19D_getObjectTypeId(void);
void dll_19D_free(int obj);
void dll_19D_render(void);
void dll_19D_hitDetect(int obj);
void dll_19D_update(int obj);
void dll_19D_init(int obj);
void dll_19D_release(void);
void dll_19D_initialise(void);

#endif /* MAIN_DLL_SHRINE1CE_H_ */
