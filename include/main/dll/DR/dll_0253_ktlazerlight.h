#ifndef MAIN_DLL_DR_DLL_0253_KTLAZERLIGHT_H_
#define MAIN_DLL_DR_DLL_0253_KTLAZERLIGHT_H_

#include "global.h"

typedef struct KtlazerlightPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x8: ObjPlacement head */
    f32 posY; /* 0xC */
    f32 posZ; /* 0x10 */
    u8 pad14[0x1A - 0x14];
    s16 onIntensityBit; /* 0x1A: game bit; value scales distance falloff */
    s16 onStayLitBit;   /* 0x1C: game bit; keeps the light lit */
    u8 pad1E[0x20 - 0x1E];
} KtlazerlightPlacement;

STATIC_ASSERT(offsetof(KtlazerlightPlacement, posX) == 0x8);
STATIC_ASSERT(offsetof(KtlazerlightPlacement, onIntensityBit) == 0x1A);
STATIC_ASSERT(offsetof(KtlazerlightPlacement, onStayLitBit) == 0x1C);
STATIC_ASSERT(sizeof(KtlazerlightPlacement) == 0x20);

int ktlazerlight_getExtraSize(void);
int ktlazerlight_getObjectTypeId(void);
void ktlazerlight_free(struct GameObject* obj);
void ktlazerlight_render(void);
void ktlazerlight_hitDetect(void);
void ktlazerlight_update(struct GameObject* obj);
void ktlazerlight_init(struct GameObject* obj, char* placement);
void ktlazerlight_release(void);
void ktlazerlight_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0253_KTLAZERLIGHT_H_ */
