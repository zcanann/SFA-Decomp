#ifndef MAIN_SKY_API_H_
#define MAIN_SKY_API_H_

#include "types.h"

void envFxActFn_800887f8(u8 value);
void modelTextureFn_80089970(int slot);
void objGetColor(int slot, u8* red, u8* green, u8* blue);
void skyFn_80088c94(int flags, int mode);
void skyFn_800894a8(int flags, f32 x, f32 y, f32 z);
void skyFn_80089710(int flags, u8 enabled, int startComplete);
void skySetOverrideLightColor(u8 red, u8 green, u8 blue);
void skySetOverrideLightColorEnabled(u8 enabled);
void skySetOverrideLightDirection(f32 x, f32 y, f32 z, f32 intensity);
void skySetOverrideLightDirectionEnabled(u8 enabled);

#endif /* MAIN_SKY_API_H_ */
