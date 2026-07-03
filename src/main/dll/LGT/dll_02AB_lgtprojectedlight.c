/*
 * lgtprojectedlight (DLL 0x2AB) - a placeable projected (gobo/spot) light.
 *
 * init creates a ModelLight of kind PROJECTED, points it from the placement
 * record and loads its projection texture (falling back to
 * PROJECTEDLIGHT_DEFAULT_TEXTURE_ASSET when none is given). It then sets up
 * either an orthographic frustum (PROJECTEDLIGHT_PROJECTION_ORTHO, with the
 * half-extents derived from projectionWidth/Height and the near/far depth from
 * the two nibbles of orthoDepthNibbles) or a perspective frustum (fovY plus the
 * height/width ratio), configures the projection TEV modes, near/far Z, colour
 * fade and target colour. update just spins the light by its per-axis rotation
 * speeds.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

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

#define PROJECTEDLIGHT_DEFAULT_TEXTURE_ASSET 0x5dc
#define PROJECTEDLIGHT_PROJECTION_ORTHO 0

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

int projectedlight_getExtraSize(void) { return sizeof(ProjectedLightState); }

int projectedlight_getObjectTypeId(void) { return 0; }

void projectedlight_free(int obj)
{
    ProjectedLightState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
    if (state->texture != NULL)
    {
        textureFree(state->texture);
    }
}

void projectedlight_hitDetect(void)
{
}

void projectedlight_render(void)
{
}

void projectedlight_update(int obj)
{
    ProjectedLightSetup* setup = (ProjectedLightSetup*)((GameObject*)obj)->anim.placementData;

    ((GameObject*)obj)->anim.rotX =
        (s16)((f32)setup->rotXSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotX);
    ((GameObject*)obj)->anim.rotY =
        (s16)((f32)setup->rotYSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotY);
    ((GameObject*)obj)->anim.rotZ =
        (s16)((f32)(setup->rotZSpeed << 4) * timeDelta + (f32)((GameObject*)obj)->anim.rotZ);
}

#pragma opt_common_subs off
void projectedlight_init(int obj, int setup)
{
    PointLightVec vec;
    ProjectedLightSetup* setupData = (ProjectedLightSetup*)setup;
    ProjectedLightState* state = ((GameObject*)obj)->extra;

    vec = *(PointLightVec*)lbl_802C2618;

    ((GameObject*)obj)->anim.rotX = (s16)(setupData->rotX << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(setupData->rotY << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)(setupData->rotZ << 8);

    if (state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }

    if (state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_PROJECTED);
        modelLightStruct_setPosition(state->light, lbl_803E7270, lbl_803E7270, lbl_803E7270);
        modelLightStruct_setDirection(state->light, vec.x, vec.y, vec.z);
        modelLightStruct_setDiffuseColor(state->light, setupData->diffuseR,
                                         setupData->diffuseG, setupData->diffuseB, setupData->alpha);
        modelLightStruct_setDistanceAttenuation(state->light, (f32)(u32)setupData->distanceNear,
                                                (f32)(u32)setupData->distanceFar);
        modelLightStruct_setProjectedLightChannelPreference(state->light, setupData->channelPreference);
        modelLightStruct_setEnabled(state->light, setupData->enabled, lbl_803E7270);

        if (state->texture == NULL)
        {
            if (setupData->textureAsset != 0)
            {
                state->texture = textureLoadAsset(setupData->textureAsset);
            }
            else
            {
                state->texture = textureLoadAsset(PROJECTEDLIGHT_DEFAULT_TEXTURE_ASSET);
            }
            modelLightStruct_setProjectionTexture(state->light, state->texture);
        }

        if (setupData->projectionMode == PROJECTEDLIGHT_PROJECTION_ORTHO)
        {
            f32 halfHeight = (f32)(u32)setupData->projectionHeight / lbl_803E7274;
            f32 halfWidth;
            f32 nearDepth, farDepth;
            if (halfHeight < lbl_803E7260)
            {
                halfHeight = lbl_803E7260;
            }
            halfWidth = (f32)(u32)setupData->projectionWidth / lbl_803E7274;
            if (halfWidth < lbl_803E7260)
            {
                halfWidth = lbl_803E7260;
            }
            if (setupData->orthoDepthNibbles != 0)
            {
                u8 depth = setupData->orthoDepthNibbles;
                nearDepth = (f32)(depth & 0xf);
                farDepth = (f32)((depth >> 4) & 0xf);
            }
            else
            {
                nearDepth = lbl_803E7260;
                farDepth = nearDepth;
            }
            modelLightStruct_setupOrthoProjection(state->light, halfWidth, -halfWidth,
                                                  -halfHeight, halfHeight, nearDepth, farDepth);
        }
        else
        {
            f32 height = (f32)(u32)setupData->projectionHeight / lbl_803E7274;
            f32 width;
            if (height < lbl_803E7260)
            {
                height = lbl_803E7260;
            }
            width = (f32)(u32)setupData->projectionWidth / lbl_803E7274;
            if (width < lbl_803E7260)
            {
                width = lbl_803E7260;
            }
            modelLightStruct_setupPerspectiveProjection(state->light, (f32)(u32)setupData->fovY, height / width);
        }

        modelLightStruct_setProjectionTevModes(state->light, setupData->tevModeA, setupData->tevModeB);
        modelLightStruct_setProjectionNearZ(state->light, (f32)(u32)setupData->nearZ);
        modelLightStruct_setProjectionFarZ(state->light, (f32)(u32)setupData->farZ);
        modelLightStruct_startColorFade(state->light, setupData->colorFadeSpeed, setupData->colorFadeFrames);
        modelLightStruct_setDiffuseTargetColor(state->light, setupData->targetR, setupData->targetG,
                                               setupData->targetB, setupData->targetAlpha);
    }
}
#pragma opt_common_subs reset

void projectedlight_release(void)
{
}

void projectedlight_initialise(void)
{
}
