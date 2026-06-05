#ifndef MAIN_MODEL_LIGHT_H_
#define MAIN_MODEL_LIGHT_H_

#include "ghidra_import.h"

typedef struct ModelLightStruct {
    void *owner;
    f32 localX;
    f32 localY;
    f32 localZ;
    f32 worldX;
    f32 worldY;
    f32 worldZ;
    f32 viewX;
    f32 viewY;
    f32 viewZ;
    u8 pad28[0x4c - 0x28];
    u8 enabled;
    u8 field4D;
    u8 pad4e[0x50 - 0x4e];
    int lightKind;
    void *field54;
    int activeState;
    int field5C;
    int transformMode;
    u8 field64;
    u8 pad65[0xa8 - 0x65];
    u8 colorA8[4];
    u8 colorAC[4];
    u8 colorB0[4];
    f32 fieldB4;
    int fieldB8;
    u8 fieldBC;
    u8 padBD[0x100 - 0xbd];
    u8 color100[4];
    u8 color104[4];
    u8 color108[4];
    f32 spotRadius;
    f32 spotBrightness;
    u8 field114;
    u8 pad115[0x124 - 0x115];
    f32 attenuationK0;
    f32 attenuationK1;
    f32 attenuationK2;
    f32 selectionScore;
    f32 lightAmount;
    f32 activeIntensity;
    f32 activeIntensityStep;
    f32 innerRadius;
    f32 outerRadius;
    u8 pad148[0x2d8 - 0x148];
    int colorFadeMode;
    f32 colorFadeStep;
    f32 colorFadeProgress;
    f32 colorFadeTimer;
    void *glowTexture;
    u8 glowColor[4];
    f32 glowScale;
    f32 glowProjectionRadius;
    u8 glowType;
    u8 glowAlpha;
    s8 glowAlphaStep;
    u8 affectsAabbLightSelection;
    u8 field2FC;
    u8 pad2fd[0x300 - 0x2fd];
} ModelLightStruct;

void queueGlowRender(ModelLightStruct *light);
void modelLightStruct_updateGlowAlpha(ModelLightStruct *light);
void modelLightStruct_updateColorFade(ModelLightStruct *light);
void modelLightStruct_startColorFade(ModelLightStruct *light, int mode, s16 frames);
void modelLightStruct_setEnabled(ModelLightStruct *light, u8 enabled, f32 duration);
int modelLightStruct_getActiveState(ModelLightStruct *light);
void modelLightStruct_setGlowProjectionRadius(ModelLightStruct *light, f32 radius);
void modelLightStruct_setGlowColor(ModelLightStruct *light, u8 red, u8 green, u8 blue, u8 alpha);
void modelLightStruct_setupGlow(ModelLightStruct *light, u32 textureId, u8 red, u8 green, u8 blue, u8 alpha, f32 scale);

#endif /* MAIN_MODEL_LIGHT_H_ */
