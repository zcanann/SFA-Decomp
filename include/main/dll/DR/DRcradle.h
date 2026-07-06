#ifndef MAIN_DLL_DR_DRCRADLE_H_
#define MAIN_DLL_DR_DRCRADLE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor24 gSnowBikeObjDescriptor;

void SnowBike_func17(void);
void SnowBike_func16(void);
int SnowBike_func0E(void);
int SnowBike_render2(void);
int SnowBike_getExtraSize(void);
int SnowBike_getObjectTypeId(void);
u8 SnowBike_func0B(int *obj);
s32 SnowBike_func14(int *obj);
s32 SnowBike_getRiderMode(int *obj);

#endif /* MAIN_DLL_DR_DRCRADLE_H_ */
