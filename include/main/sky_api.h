#ifndef MAIN_SKY_API_H_
#define MAIN_SKY_API_H_

#include "types.h"

typedef struct ModelLightStruct ModelLightStruct;
typedef struct GameObject GameObject;

void skySetEnvFxFlags(u8 value);
f32 lightningGetRemainingFraction(void);
void skyGetObjectLightDirection(GameObject* obj, f32* x, f32* y, f32* z);
void skyApplyLightSlot(int slot);
void skyGetAmbientColor(int slot, u8* red, u8* green, u8* blue);
void objGetSunColor(int slot, u8* red, u8* green, u8* blue);
u8 skyGetSlotFlag80(int slot);
void skySetSlotFlag80(int flags, u8 mode);
void skySetLightIndex(int mode, f32 brightness);
void skySetLightDirection(int flags, f32 x, f32 y, f32 z);
void skySetAmbientColor(int flags, u8 red, u8 green, u8 blue);
void skySetMoonColor(int flags, u8 red, u8 green, u8 blue);
void skySetBaseColor(int flags, u8 red, u8 green, u8 blue, u8 moonScale, u8 ambientScale);
void skySetLightsEnabled(int flags, u8 enabled, int startComplete);
void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
void skySetOverrideLightColorEnabled(u8 enabled);
void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
void skySetOverrideLightDirectionEnabled(u8 enabled);
ModelLightStruct* skyGetMoonLight(void);
ModelLightStruct* skyGetSunLight(void);

#endif /* MAIN_SKY_API_H_ */
