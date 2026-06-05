#ifndef MAIN_MODEL_LIGHT_H_
#define MAIN_MODEL_LIGHT_H_

#include "ghidra_import.h"

typedef struct ModelLightStruct {
    u8 pad0[0x10];
    f32 worldX;
    f32 worldY;
    f32 worldZ;
    u8 pad1[0x4c - 0x1c];
    u8 enabled;
    u8 pad4d[0x140 - 0x4d];
    f32 innerRadius;
    f32 outerRadius;
    u8 pad148[0x2f8 - 0x148];
    u8 type;
    u8 glowAlpha;
    s8 glowAlphaStep;
    u8 pad2fb[0x300 - 0x2fb];
} ModelLightStruct;

void queueGlowRender(ModelLightStruct *light);

#endif /* MAIN_MODEL_LIGHT_H_ */
