#ifndef MAIN_DLL_DLL_00DD_GCBADDIESHIELD_API_H_
#define MAIN_DLL_DLL_00DD_GCBADDIESHIELD_API_H_

#include "types.h"

void GCbaddieShield_free(void);
int GCbaddieShield_getExtraSize(void);
int GCbaddieShield_getObjectTypeId(void);
void GCbaddieShield_hitDetect(void);
void GCbaddieShield_init(int* obj, void* initData);
void GCbaddieShield_initialise(void);
void GCbaddieShield_release(void);
void GCbaddieShield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void GCbaddieShield_update(int* obj);

#endif /* MAIN_DLL_DLL_00DD_GCBADDIESHIELD_API_H_ */
