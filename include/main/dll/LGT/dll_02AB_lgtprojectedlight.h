#ifndef MAIN_DLL_LGT_DLL_02AB_LGTPROJECTEDLIGHT_H_
#define MAIN_DLL_LGT_DLL_02AB_LGTPROJECTEDLIGHT_H_

#include "main/game_object.h"
#include "main/dll/dll_80220608_shared.h"

typedef struct ProjectedLightSetup
{
    ObjPlacement base;
    u8 rotX;
    u8 rotY;
    u16 distanceNear;
    u16 distanceFar;
    s16 colorFadeFrames;
    s16 rotXSpeed;
    s16 rotYSpeed;
    u16 textureAsset;
    u8 projectionMode;
    u8 fovY;
    u16 projectionHeight;
    u16 projectionWidth;
    u8 pad2C;
    u8 diffuseR;
    u8 diffuseG;
    u8 diffuseB;
    u8 targetR;
    u8 targetG;
    u8 targetB;
    u8 colorFadeSpeed;
    u8 rotZ;
    s8 rotZSpeed;
    u8 tevModeA;
    u8 alpha;
    u8 targetAlpha;
    u8 channelPreference;
    u8 enabled;
    u8 nearZ;
    u16 farZ;
    u8 tevModeB;
    u8 orthoDepthNibbles;
} ProjectedLightSetup;

typedef struct ProjectedLightState
{
    ModelLight* light;
    void* texture;
} ProjectedLightState;

STATIC_ASSERT(sizeof(ProjectedLightState) == 0x8);
STATIC_ASSERT(offsetof(ProjectedLightState, texture) == 0x04);
STATIC_ASSERT(offsetof(ProjectedLightSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(ProjectedLightSetup, distanceNear) == 0x1A);
STATIC_ASSERT(offsetof(ProjectedLightSetup, colorFadeFrames) == 0x1E);
STATIC_ASSERT(offsetof(ProjectedLightSetup, rotXSpeed) == 0x20);
STATIC_ASSERT(offsetof(ProjectedLightSetup, textureAsset) == 0x24);
STATIC_ASSERT(offsetof(ProjectedLightSetup, projectionMode) == 0x26);
STATIC_ASSERT(offsetof(ProjectedLightSetup, diffuseR) == 0x2D);
STATIC_ASSERT(offsetof(ProjectedLightSetup, colorFadeSpeed) == 0x33);
STATIC_ASSERT(offsetof(ProjectedLightSetup, rotZ) == 0x34);
STATIC_ASSERT(offsetof(ProjectedLightSetup, rotZSpeed) == 0x35);
STATIC_ASSERT(offsetof(ProjectedLightSetup, tevModeA) == 0x36);
STATIC_ASSERT(offsetof(ProjectedLightSetup, alpha) == 0x37);
STATIC_ASSERT(offsetof(ProjectedLightSetup, channelPreference) == 0x39);
STATIC_ASSERT(offsetof(ProjectedLightSetup, enabled) == 0x3A);
STATIC_ASSERT(offsetof(ProjectedLightSetup, nearZ) == 0x3B);
STATIC_ASSERT(offsetof(ProjectedLightSetup, farZ) == 0x3C);
STATIC_ASSERT(offsetof(ProjectedLightSetup, tevModeB) == 0x3E);
STATIC_ASSERT(offsetof(ProjectedLightSetup, orthoDepthNibbles) == 0x3F);
STATIC_ASSERT(sizeof(ProjectedLightSetup) == 0x40);

int ProjectedLight_getExtraSize(void);
int ProjectedLight_getObjectTypeId(void);
void ProjectedLight_free(GameObject* obj);
void ProjectedLight_render(void);
void ProjectedLight_hitDetect(void);
void ProjectedLight_update(GameObject* obj);
void ProjectedLight_init(GameObject* obj, int setup);
void ProjectedLight_release(void);
void ProjectedLight_initialise(void);

#endif /* MAIN_DLL_LGT_DLL_02AB_LGTPROJECTEDLIGHT_H_ */
