#ifndef MAIN_MODELLIGHT_API_H_
#define MAIN_MODELLIGHT_API_H_

#include "global.h"

typedef struct ModelLightStruct ModelLightStruct;

void modelLightChannels_applyGXControls(void);
void modelLightChannels_reset(u8 useModelRelative);
void modelLightChannel_configure(int channel, int mode, int materialSource);
void updateLights(void);
void lightGetColor(int index, u8* red, u8* green, u8* blue);

int modelLightStruct_getActiveState(ModelLightStruct* light);
void modelLightStruct_getDiffuseColor(ModelLightStruct* light, u8* red, u8* green, u8* blue, u8* alpha);
void lightSetField4D(ModelLightStruct* light, u8 value);
void lightSetFieldBC_8001db14(ModelLightStruct* light, u8 value);
void modelLightStruct_setGlowProjectionRadius(ModelLightStruct* light, f32 radius);
void modelLightStruct_setAffectsAabbLightSelection(ModelLightStruct* light, u8 enabled);
void modelLightStruct_setSpecularTargetColor(ModelLightStruct* light, u8 red, u8 green, u8 blue, u8 alpha);
void modelLightStruct_getSpecularColor(ModelLightStruct* light, u8* red, u8* green, u8* blue, u8* alpha);
void modelLightStruct_setGlowColor(ModelLightStruct* light, u8 red, u8 green, u8 blue, u8 alpha);
void modelLightStruct_setAngularAttenuation(ModelLightStruct* light, f32 a0, f32 a1, f32 a2);
void modelLightStruct_setSpecularAttenuation(ModelLightStruct* light, f32 scale, f32 brightness);

#endif /* MAIN_MODELLIGHT_API_H_ */
