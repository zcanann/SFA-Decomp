#ifndef MAIN_MODELLIGHT_API_H_
#define MAIN_MODELLIGHT_API_H_

#include "global.h"

typedef struct ModelLightStruct ModelLightStruct;

void lightSetField4D(ModelLightStruct* light, u8 value);
void lightSetFieldBC_8001db14(ModelLightStruct* light, u8 value);
void modelLightStruct_setGlowProjectionRadius(ModelLightStruct* light, f32 radius);
void modelLightStruct_setAffectsAabbLightSelection(ModelLightStruct* light, u8 enabled);
void modelLightStruct_setSpecularTargetColor(ModelLightStruct* light, u8 red, u8 green, u8 blue, u8 alpha);

#endif /* MAIN_MODELLIGHT_API_H_ */
