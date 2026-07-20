#ifndef MAIN_SKY_API_H_
#define MAIN_SKY_API_H_

#include "types.h"

typedef struct ModelLightStruct ModelLightStruct;
typedef struct GameObject GameObject;

void envFxActFn_800887f8(u8 value);
f32 lightningGetRemainingFraction(void);
void fn_8008923C(GameObject* obj, f32* x, f32* y, f32* z);
void modelTextureFn_80089970(int slot);
void textureColorFn_8008991c(int slot, u8* red, u8* green, u8* blue);
void objGetColor(int slot, u8* red, u8* green, u8* blue);
int getSkyColorFn_80088e08(int slot);
void skyFn_80088c94(int flags, u8 mode);
void skyFn_80088e54(int mode, f32 brightness);
void skySetLightDirection(int flags, f32 x, f32 y, f32 z);
void skySetLightColor(int flags, u8 red, u8 green, u8 blue);
void skySetAmbientColor(int flags, u8 red, u8 green, u8 blue);
void skySetBaseColor(int flags, u8 red, u8 green, u8 blue, u8 ambientScale, u8 lightScale);
void skyFn_80089710(int flags, u8 enabled, int startComplete);
void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
void skySetOverrideLightColorEnabled(u8 enabled);
void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
void skySetOverrideLightDirectionEnabled(u8 enabled);
ModelLightStruct* skyGetMoonLight(void);
ModelLightStruct* skyGetSunLight(void);

#define getSkyColorFn_80088e08ByteLegacy(slot) \
    ((u8 (*)(int))getSkyColorFn_80088e08)((slot))

#endif /* MAIN_SKY_API_H_ */
