#ifndef MAIN_MODEL_LIGHT_H_
#define MAIN_MODEL_LIGHT_H_

#include "ghidra_import.h"
#include "main/modellight_api.h"

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
    f32 localDirX;
    f32 localDirY;
    f32 localDirZ;
    f32 worldDirX;
    f32 worldDirY;
    f32 worldDirZ;
    f32 viewDirX;
    f32 viewDirY;
    f32 viewDirZ;
    u8 enabled;
    u8 field4D;
    u8 pad4e[0x50 - 0x4e];
    int lightKind;
    int projectedLightChannelPreference;
    int activeState;
    int objectLightMaskIndex;
    int transformMode;
    u8 objectLightMask;
    u8 pad65[0xa8 - 0x65];
    u8 diffuseColor[4];
    u8 diffuseFadeStartColor[4];
    u8 diffuseFadeTargetColor[4];
    f32 spotCutoff;
    int spotFunction;
    u8 fieldBC;
    u8 padBD[0x100 - 0xbd];
    u8 specularColor[4];
    u8 specularFadeStartColor[4];
    u8 specularFadeTargetColor[4];
    f32 specularAttenuationScale;
    f32 specularBrightness;
    u8 field114;
    u8 pad115[0x124 - 0x115];
    f32 attenuationK0;
    f32 attenuationK1;
    f32 attenuationK2;
    f32 selectionScore;
    f32 lightAmount;
    f32 activeIntensity;
    f32 activeIntensityStep;
    f32 attenuationNear;
    f32 attenuationFar;
    f32 projectionFovY;
    f32 projectionAspect;
    f32 projectionTop;
    f32 projectionBottom;
    f32 projectionLeft;
    f32 projectionRight;
    f32 projectionNearZ;
    f32 projectionFarZ;
    int projectionType;
    void *projectionTexture;
    f32 inverseWorldProjectionMtx[16];
    f32 lightProjectionTexMtx[16];
    f32 lightProjectionClipMtx[16];
    f32 projectionTexMtx[16];
    int projectionTevColorMode;
    int projectionTevAlphaMode;
    u8 pad278[0x2d8 - 0x278];
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
    u8 selectionPriority;
    u8 pad2fd[0x300 - 0x2fd];
} ModelLightStruct;

typedef ModelLightStruct ModelLight;

enum ModelLightKind
{
    MODEL_LIGHT_KIND_POINT = 2,
    MODEL_LIGHT_KIND_DIRECTIONAL = 4,
    MODEL_LIGHT_KIND_PROJECTED = 8
};

ModelLightStruct* objCreateLight(void* owner, u8 addToList);
ModelLightStruct* modelLightStruct_createPointLight(void* owner, u8 red, u8 green, u8 blue, u8 setFlag);
void modelLightStruct_freeSlot(ModelLightStruct** lightSlot);
void objSetEventName(ModelLightStruct* light, int name);
void ModelLightStruct_free(ModelLightStruct* light);

void queueGlowRender(ModelLightStruct *light);
void modelLightStruct_updateGlowAlpha(ModelLightStruct *light);
void modelLightStruct_updateColorFade(ModelLightStruct *light);
void modelLightStruct_startColorFade(ModelLightStruct *light, int mode, s16 frames);
void modelLightStruct_setEnabled(ModelLightStruct* light, int enabled, f32 duration);
int modelLightStruct_getActiveState(ModelLightStruct *light);
void modelLightStruct_setLightKind(ModelLightStruct *light, int lightKind);
void modelLightStruct_setObjectLightMaskIndex(ModelLightStruct *light, int objectLightMaskIndex);
void modelLightStruct_setDistanceAttenuation(ModelLightStruct* light, f32 near, f32 far);
void modelLightStruct_setDiffuseTargetColor(ModelLightStruct* light, int red, int green, int blue, int alpha);
void modelLightStruct_getDiffuseColor(ModelLightStruct *light, u8 *red, u8 *green, u8 *blue, u8 *alpha);
void modelLightStruct_setDiffuseColor(ModelLightStruct *light, u8 red, u8 green, u8 blue, u8 alpha);
void modelLightStruct_setSpecularColor(ModelLightStruct *light, u8 red, u8 green, u8 blue, u8 alpha);
void modelLightStruct_setSpotAttenuation(ModelLightStruct *light, f32 cutoff, int spotFunction);
void modelLightStruct_setPosition(ModelLightStruct *light, f32 x, f32 y, f32 z);
void modelLightStruct_setDirection(ModelLightStruct *light, f32 x, f32 y, f32 z);
int modelLightStruct_getProjectedLightChannelPreference(ModelLightStruct *light);
void modelLightStruct_setProjectedLightChannelPreference(ModelLightStruct *light, int preference);
void modelLightStruct_setSelectionPriority(ModelLightStruct *light, u8 priority);
f32 *modelLightStruct_getProjectionTexMtx(ModelLightStruct *light);
void *modelLightStruct_getProjectionTexture(ModelLightStruct *light);
void modelLightStruct_setProjectionTexture(ModelLightStruct *light, void *texture);
void modelLightStruct_getProjectionTevModes(ModelLightStruct *light, void **colorMode, void **alphaMode);
void modelLightStruct_setProjectionTevModes(ModelLightStruct* light, int colorMode, int alphaMode);
void modelLightStruct_setProjectionNearZ(ModelLightStruct *light, f32 nearZ);
void modelLightStruct_setProjectionFarZ(ModelLightStruct *light, f32 farZ);
void modelLightStruct_setupPerspectiveProjection(ModelLightStruct *light, f32 fovY, f32 aspect);
void modelLightStruct_setupOrthoProjection(ModelLightStruct *light, f32 top, f32 bottom, f32 left, f32 right, f32 scaleS, f32 scaleT);
void modelLightStruct_setupGlow(ModelLightStruct *light, u32 textureId, u8 red, u8 green, u8 blue, u8 alpha, f32 scale);

#endif /* MAIN_MODEL_LIGHT_H_ */
