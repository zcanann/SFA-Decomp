#ifndef MAIN_DLL_LGT_DLL_02A9_LGTPOINTLIGHT_H_
#define MAIN_DLL_LGT_DLL_02A9_LGTPOINTLIGHT_H_

#include "main/game_object.h"
#include "main/dll/dll_80220608_shared.h"

typedef struct PointLightState
{
    ModelLight* light;
    u8 enabled;
} PointLightState;

typedef struct PointLightSetup
{
    ObjPlacement base;
    u8 rotX;
    u8 rotY;
    u8 diffuseR;
    u8 diffuseG;
    u8 diffuseB;
    u8 eventName;
    s16 enableBit;
    u8 brightness;
    u8 spotMode;
    u16 distanceNear;
    u16 distanceFar;
    u8 colorFadeSpeed;
    u8 targetR;
    u8 targetG;
    u8 targetB;
    u8 flags;
    u8 pad2B;
    u8 selectionPriority;
    u8 pad2D;
    s16 colorFadeFrames;
    u8 enabled;
    u8 pad31;
    s16 rotXSpeed;
    s16 rotYSpeed;
    u16 glowScale;
    u16 glowTexture;
    u8 glowR;
    u8 glowG;
    u8 glowB;
    u8 glowAlpha;
    u8 glowEnabled;
    u8 affectsAabbLightSelection;
} PointLightSetup;

STATIC_ASSERT(sizeof(PointLightState) == 0x8);
STATIC_ASSERT(offsetof(PointLightState, enabled) == 0x04);
STATIC_ASSERT(offsetof(PointLightSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(PointLightSetup, diffuseR) == 0x1A);
STATIC_ASSERT(offsetof(PointLightSetup, eventName) == 0x1D);
STATIC_ASSERT(offsetof(PointLightSetup, enableBit) == 0x1E);
STATIC_ASSERT(offsetof(PointLightSetup, brightness) == 0x20);
STATIC_ASSERT(offsetof(PointLightSetup, distanceNear) == 0x22);
STATIC_ASSERT(offsetof(PointLightSetup, colorFadeSpeed) == 0x26);
STATIC_ASSERT(offsetof(PointLightSetup, targetR) == 0x27);
STATIC_ASSERT(offsetof(PointLightSetup, flags) == 0x2A);
STATIC_ASSERT(offsetof(PointLightSetup, selectionPriority) == 0x2C);
STATIC_ASSERT(offsetof(PointLightSetup, colorFadeFrames) == 0x2E);
STATIC_ASSERT(offsetof(PointLightSetup, enabled) == 0x30);
STATIC_ASSERT(offsetof(PointLightSetup, rotXSpeed) == 0x32);
STATIC_ASSERT(offsetof(PointLightSetup, rotYSpeed) == 0x34);
STATIC_ASSERT(offsetof(PointLightSetup, glowScale) == 0x36);
STATIC_ASSERT(offsetof(PointLightSetup, glowTexture) == 0x38);
STATIC_ASSERT(offsetof(PointLightSetup, glowR) == 0x3A);
STATIC_ASSERT(offsetof(PointLightSetup, glowEnabled) == 0x3E);
STATIC_ASSERT(offsetof(PointLightSetup, affectsAabbLightSelection) == 0x3F);
STATIC_ASSERT(sizeof(PointLightSetup) == 0x40);

void pointlight_setEffectState(GameObject* obj, int enabled);
int PointLight_getExtraSize(void);
int PointLight_getObjectTypeId(void);
void PointLight_free(int obj);
void PointLight_render(GameObject* obj);
void PointLight_hitDetect(void);
void PointLight_update(GameObject* obj);
void PointLight_init(int obj, int setup);
void PointLight_release(void);
void PointLight_initialise(void);

#endif /* MAIN_DLL_LGT_DLL_02A9_LGTPOINTLIGHT_H_ */
