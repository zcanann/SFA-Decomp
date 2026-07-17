#ifndef MAIN_DLL_DR_DLL_0253_KTLAZERLIGHT_H_
#define MAIN_DLL_DR_DLL_0253_KTLAZERLIGHT_H_

#include "main/game_object.h"
#include "main/model_light.h"
#include "global.h"

typedef struct KtlazerlightState
{
    u8 pad00[4];
    ModelLightStruct* light; /* 0x04 */
    u8 pad08[0x14 - 0x08];
} KtlazerlightState;

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
STATIC_ASSERT(offsetof(KtlazerlightState, light) == 0x04);
STATIC_ASSERT(sizeof(KtlazerlightState) == 0x14);

union KtLazerLightConstF32;
extern const union KtLazerLightConstF32 lbl_803E68C0;

int ktlazerlight_getExtraSize(void);
int ktlazerlight_getObjectTypeId(void);
void ktlazerlight_free(GameObject* obj);
void ktlazerlight_render(void);
void ktlazerlight_hitDetect(void);
void ktlazerlight_update(GameObject* obj);
void ktlazerlight_init(GameObject* obj, KtlazerlightPlacement* placement);
void ktlazerlight_release(void);
void ktlazerlight_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0253_KTLAZERLIGHT_H_ */
