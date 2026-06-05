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
    void *field58;
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
    f32 selectionIntensity;
    f32 field134;
    u8 pad138[0x140 - 0x138];
    f32 innerRadius;
    f32 outerRadius;
    u8 pad148[0x2f8 - 0x148];
    u8 type;
    u8 glowAlpha;
    s8 glowAlphaStep;
    u8 affectsAabbLightSelection;
    u8 field2FC;
    u8 pad2fd[0x300 - 0x2fd];
} ModelLightStruct;

void queueGlowRender(ModelLightStruct *light);

#endif /* MAIN_MODEL_LIGHT_H_ */
