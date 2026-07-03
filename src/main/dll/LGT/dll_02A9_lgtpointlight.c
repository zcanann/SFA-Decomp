/*
 * lgtpointlight (DLL 0x2A9) - a placeable point light.
 *
 * On init it creates a ModelLight of kind POINT and configures it from the
 * placement record: diffuse colour (or the live ambient colour when
 * POINTLIGHT_FLAG_USE_AMBIENT_COLOR is set), distance attenuation, spot
 * attenuation (brightness clamped to POINTLIGHT_MAX_SPOT_BRIGHTNESS), an
 * initial colour fade, direction, an optional billboard glow, AABB
 * light-selection participation and a selection priority. update() spins the
 * light by its per-axis rotation speeds, toggles the light on/off from its
 * enableBit game bit, refreshes the ambient colour each frame when requested
 * and advances the glow alpha.
 *
 * Each instance joins LGT_POINTLIGHT_GROUP so lgtcontrollight can toggle the
 * point lights within a radius; pointlight_setEffectState is the entry point
 * it calls.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct PointLightState
{
    ModelLight* light;
    u8 enabled;
} PointLightState;

#define POINTLIGHT_FLAG_USE_AMBIENT_COLOR 0x01
#define POINTLIGHT_MAX_SPOT_BRIGHTNESS 0x5a

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

int pointlight_getExtraSize(void) { return sizeof(PointLightState); }

int pointlight_getObjectTypeId(void) { return 0; }

void pointlight_setEffectState(int obj, int enabled)
{
    GameObject* object = (GameObject*)obj;
    PointLightState* state = object->extra;
    ModelLight* light = state->light;
    if (light != NULL)
    {
        modelLightStruct_setEnabled(light, enabled, lbl_803E7230);
    }
}

void pointlight_free(int obj)
{
    PointLightState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
    ObjGroup_RemoveObject(obj, LGT_POINTLIGHT_GROUP);
}

void pointlight_render(int obj)
{
    PointLightState* state = ((GameObject*)obj)->extra;
    ModelLight* light = state->light;
    if (light != NULL && *(u8*)((char*)light + 0x2f8) != 0 &&
        *(u8*)((char*)light + 0x4c) != 0)
    {
        queueGlowRender(light);
    }
}

void pointlight_hitDetect(void)
{
}

void pointlight_update(int obj)
{
    u8 colorR, colorG, colorB;
    PointLightSetup* setup = (PointLightSetup*)((GameObject*)obj)->anim.placementData;
    PointLightState* state = ((GameObject*)obj)->extra;

    if (state->light == NULL)
    {
        return;
    }

    ((GameObject*)obj)->anim.rotX =
        (s16)((f32)setup->rotXSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotX);
    ((GameObject*)obj)->anim.rotY =
        (s16)((f32)setup->rotYSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotY);

    if (state->enabled != 0)
    {
        s16 bit = setup->enableBit;
        if (bit > 0 && GameBit_Get(bit) == 0)
        {
            state->enabled = 0;
            modelLightStruct_setEnabled(state->light, 0, lbl_803E7234);
        }
        if ((setup->flags & POINTLIGHT_FLAG_USE_AMBIENT_COLOR) != 0)
        {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        }
    }
    else
    {
        s16 bit = setup->enableBit;
        if (bit > 0 && GameBit_Get(bit) != 0)
        {
            state->enabled = 1;
            modelLightStruct_setEnabled(state->light, 1, lbl_803E7234);
        }
    }

    if (state->light != NULL)
    {
        modelLightStruct_updateGlowAlpha(state->light);
    }
}

void pointlight_init(int obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    PointLightSetup* setupData = (PointLightSetup*)setup;
    PointLightState* state = ((GameObject*)obj)->extra;

    vec = *(PointLightVec*)lbl_802C25F8;

    ((GameObject*)obj)->anim.rotX = (s16)(setupData->rotX << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(setupData->rotY << 8);

    if (state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }

    if (state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
        objSetEventName(state->light, setupData->eventName);
        modelLightStruct_setPosition(state->light, 0.0f, 0.0f, 0.0f);

        if ((setupData->flags & POINTLIGHT_FLAG_USE_AMBIENT_COLOR) != 0)
        {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        }
        else
        {
            modelLightStruct_setDiffuseColor(state->light, setupData->diffuseR,
                                             setupData->diffuseG, setupData->diffuseB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, setupData->targetR,
                                                   setupData->targetG, setupData->targetB, 0xff);
        }

        modelLightStruct_setDistanceAttenuation(state->light, (f32)(u32)setupData->distanceNear,
                                                (f32)(u32)setupData->distanceFar);

        {
            int brightness = (u32)setupData->brightness < POINTLIGHT_MAX_SPOT_BRIGHTNESS
                                 ? setupData->brightness
                                 : POINTLIGHT_MAX_SPOT_BRIGHTNESS;
            modelLightStruct_setSpotAttenuation(state->light, brightness, setupData->spotMode);
        }

        modelLightStruct_setEnabled(state->light, setupData->enabled, lbl_803E7230);
        state->enabled = setupData->enabled;
        modelLightStruct_startColorFade(state->light, setupData->colorFadeSpeed, setupData->colorFadeFrames);
        modelLightStruct_setDirection(state->light, vec.x, vec.y, vec.z);

        if (setupData->spotMode != 0)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        else
        {
            Obj_SetActiveModelIndex(obj, 0);
        }

        if (setupData->glowEnabled != 0)
        {
            modelLightStruct_setupGlow(state->light, setupData->glowTexture, setupData->glowR,
                                       setupData->glowG, setupData->glowB, setupData->glowAlpha,
                                       (f32)(u32)setupData->glowScale);
            modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E7240);
        }

        if (setupData->affectsAabbLightSelection != 0)
        {
            modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
        }

        if (setupData->selectionPriority != 0)
        {
            modelLightStruct_setSelectionPriority(state->light, setupData->selectionPriority);
        }
    }

    ObjGroup_AddObject(obj, LGT_POINTLIGHT_GROUP);
}

void pointlight_release(void)
{
}

void pointlight_initialise(void)
{
}
