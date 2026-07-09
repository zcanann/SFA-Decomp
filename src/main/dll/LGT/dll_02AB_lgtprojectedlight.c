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
#include "main/dll/LGT/dll_02AB_lgtprojectedlight.h"

#define PROJECTEDLIGHT_DEFAULT_TEXTURE_ASSET 0x5dc
#define PROJECTEDLIGHT_PROJECTION_ORTHO      0

int ProjectedLight_getExtraSize(void)
{
    return sizeof(ProjectedLightState);
}

int ProjectedLight_getObjectTypeId(void)
{
    return 0;
}

void ProjectedLight_free(struct GameObject *obj)
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

void ProjectedLight_render(void)
{
}

void ProjectedLight_hitDetect(void)
{
}

void ProjectedLight_update(struct GameObject *obj)
{
    ProjectedLightSetup* setup = (ProjectedLightSetup*)((GameObject*)obj)->anim.placementData;

    ((GameObject*)obj)->anim.rotX = (s16)((f32)setup->rotXSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotX);
    ((GameObject*)obj)->anim.rotY = (s16)((f32)setup->rotYSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotY);
    ((GameObject*)obj)->anim.rotZ =
        (s16)((f32)(setup->rotZSpeed << 4) * timeDelta + (f32)((GameObject*)obj)->anim.rotZ);
}

#pragma opt_common_subs off
void ProjectedLight_init(int obj, int setup)
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
        modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);
        modelLightStruct_setDirection(state->light, vec.x, vec.y, vec.z);
        modelLightStruct_setDiffuseColor(state->light, setupData->diffuseR, setupData->diffuseG, setupData->diffuseB,
                                         setupData->alpha);
        modelLightStruct_setDistanceAttenuation(state->light, (f32)(u32)setupData->distanceNear,
                                                (f32)(u32)setupData->distanceFar);
        modelLightStruct_setProjectedLightChannelPreference(state->light, setupData->channelPreference);
        modelLightStruct_setEnabled(state->light, setupData->enabled, 0.0f);

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
            f32 halfHeight = (f32)(u32)setupData->projectionHeight / 10.0f;
            f32 halfWidth;
            f32 nearDepth, farDepth;
            if (halfHeight < lbl_803E7260)
            {
                halfHeight = lbl_803E7260;
            }
            halfWidth = (f32)(u32)setupData->projectionWidth / 10.0f;
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
            modelLightStruct_setupOrthoProjection(state->light, halfWidth, -halfWidth, -halfHeight, halfHeight,
                                                  nearDepth, farDepth);
        }
        else
        {
            f32 height = (f32)(u32)setupData->projectionHeight / 10.0f;
            f32 width;
            if (height < lbl_803E7260)
            {
                height = lbl_803E7260;
            }
            width = (f32)(u32)setupData->projectionWidth / 10.0f;
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
        modelLightStruct_setDiffuseTargetColor(state->light, setupData->targetR, setupData->targetG, setupData->targetB,
                                               setupData->targetAlpha);
    }
}
#pragma opt_common_subs reset

void ProjectedLight_release(void)
{
}

void ProjectedLight_initialise(void)
{
}
