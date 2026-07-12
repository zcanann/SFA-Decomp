/*
 * lgtdirectionallight (DLL 0x2AA) - a placeable directional light.
 *
 * init creates a ModelLight of kind DIRECTIONAL and configures its direction,
 * diffuse colour (or the live ambient colour when the
 * DIRECTIONALLIGHT_FLAG_USE_AMBIENT_COLOR flag is set), initial colour fade and
 * selection priority. update spins the light by its per-axis rotation speeds,
 * toggles it from its enableBit game bit and refreshes the ambient colour each
 * frame when requested.
 *
 * directionallight_debugEdit is a developer tool reached from update: pressing
 * Z toggles edit mode, Up/Down cycle through DIRECTIONALLIGHT_DEBUG_FIELD_COUNT
 * editable fields (rotX, rotY, then the diffuse and target RGB channels) and
 * Left/Right nudge the selected field, echoing the value through the debug
 * text helper logPrintf.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/sky_state.h"
#include "main/game_object.h"
#include "dolphin/pad.h"
#include "main/dll/LGT/dll_02AA_lgtdirectionallight.h"

#define DIRECTIONALLIGHT_FLAG_USE_AMBIENT_COLOR 0x01
#define DIRECTIONALLIGHT_DEBUG_FIELD_COUNT      8

struct DirectionalLightObjDescriptorLayout gDirectionalLightObjDescriptor = {
    0,
    0,
    0,
    0x90000,
    {
        (void (*)(void))directionallight_initialise,
        (void (*)(void))directionallight_release,
        0,
        (void (*)(void))directionallight_init,
        (void (*)(void))directionallight_update,
        (void (*)(void))directionallight_hitDetect,
        (void (*)(void))directionallight_render,
        (void (*)(void))directionallight_free,
        (void (*)(void))directionallight_getObjectTypeId,
        (void (*)(void))directionallight_getExtraSize,
    },
    "Mode: YAW\n\000\000Angle: %d\n\000\000Mode: PITCH\n\000\000\000\000Mode: DIFFUSE COLOUR RED\n\000\000\000Colour: "
    "%d\n\000Mode: DIFFUSE COLOUR GREEN\n\000Mode: DIFFUSE COLOUR BLUE\n\000\000Mode: SPECULAR COLOUR "
    "RED\n\000\000Mode: SPECULAR COLOUR GREEN\n\000\000\000\000Mode: SPECULAR COLOUR BLUE\n",
};

void directionallight_debugEdit(GameObject* obj, int statePtr)
{
    DirectionalLightState* state = (DirectionalLightState*)statePtr;
    u8* desc = (u8*)&gDirectionalLightObjDescriptor;
    u16 buttons = getButtonsJustPressed(0);

    if ((buttons & PAD_TRIGGER_Z) != 0)
    {
        state->debugEditing ^= 1;
    }
    if (state->debugEditing == 0)
    {
        return;
    }
    if ((buttons & PAD_BUTTON_UP) != 0)
    {
        state->debugField += 1;
    }
    if ((buttons & PAD_BUTTON_DOWN) != 0)
    {
        state->debugField -= 1;
    }
    if (state->debugField >= DIRECTIONALLIGHT_DEBUG_FIELD_COUNT)
    {
        state->debugField = 0;
    }
    if (state->debugField < 0)
    {
        state->debugField = DIRECTIONALLIGHT_DEBUG_FIELD_COUNT - 1;
    }

    switch (state->debugField)
    {
    case 0:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            obj->anim.rotX -= 0x3e8;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            obj->anim.rotX += 0x3e8;
        }
        logPrintf(desc + 0x38);
        logPrintf(desc + 0x44, obj->anim.rotX);
        break;
    case 1:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            obj->anim.rotY -= 0x3e8;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            obj->anim.rotY += 0x3e8;
        }
        logPrintf(desc + 0x50);
        logPrintf(desc + 0x44, obj->anim.rotY);
        break;
    case 2:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            state->diffuseR -= 5;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            state->diffuseR += 5;
        }
        logPrintf(desc + 0x60);
        logPrintf(desc + 0x7c, state->diffuseR);
        break;
    case 3:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            state->diffuseG -= 5;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            state->diffuseG += 5;
        }
        logPrintf(desc + 0x88);
        logPrintf(desc + 0x7c, state->diffuseG);
        break;
    case 4:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            state->diffuseB -= 5;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            state->diffuseB += 5;
        }
        logPrintf(desc + 0xa4);
        logPrintf(desc + 0x7c, state->diffuseB);
        break;
    case 5:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            state->targetR -= 5;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            state->targetR += 5;
        }
        logPrintf(desc + 0xc0);
        logPrintf(desc + 0x7c, state->targetR);
        break;
    case 6:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            state->targetG -= 5;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            state->targetG += 5;
        }
        logPrintf(desc + 0xdc);
        logPrintf(desc + 0x7c, state->targetG);
        break;
    case 7:
        if ((buttons & PAD_BUTTON_LEFT) != 0)
        {
            state->targetB -= 5;
        }
        if ((buttons & PAD_BUTTON_RIGHT) != 0)
        {
            state->targetB += 5;
        }
        logPrintf(desc + 0xfc);
        logPrintf(desc + 0x7c, state->targetB);
        break;
    }
}

int directionallight_getExtraSize(void)
{
    return sizeof(DirectionalLightState);
}

int directionallight_getObjectTypeId(void)
{
    return 0;
}

void directionallight_free(GameObject* obj)
{
    DirectionalLightState* state = obj->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
    }
}

void directionallight_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7254);
}

void directionallight_hitDetect(void)
{
}

void directionallight_update(GameObject* obj)
{
    u8 colorR, colorG, colorB;
    DirectionalLightState* state = (obj)->extra;
    DirectionalLightSetup* setup = (DirectionalLightSetup*)(obj)->anim.placementData;

    if (state->light == NULL)
    {
        return;
    }

    (obj)->anim.rotX = (s16)((f32)setup->rotXSpeed * timeDelta + (f32)(obj)->anim.rotX);
    (obj)->anim.rotY = (s16)((f32)setup->rotYSpeed * timeDelta + (f32)(obj)->anim.rotY);

    if (state->enabled != 0)
    {
        if ((u32)mainGetBit(setup->enableBit) == 0)
        {
            state->enabled = 0;
            modelLightStruct_setEnabled(state->light, 0, lbl_803E7254);
        }
        if ((setup->flags & DIRECTIONALLIGHT_FLAG_USE_AMBIENT_COLOR) != 0)
        {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
        }
    }
    else
    {
        if ((u32)mainGetBit(setup->enableBit) != 0)
        {
            state->enabled = 1;
            modelLightStruct_setEnabled(state->light, 1, lbl_803E7254);
        }
    }

    directionallight_debugEdit(obj, (int)state);
}

void directionallight_init(GameObject* obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    DirectionalLightSetup* setupData = (DirectionalLightSetup*)setup;
    DirectionalLightState* state = (obj)->extra;

    vec = *(PointLightVec*)lbl_802C2608;

    (obj)->anim.rotX = (s16)(setupData->rotX << 8);
    (obj)->anim.rotY = (s16)(setupData->rotY << 8);

    if (state->light == NULL)
    {
        state->light = objCreateLight(obj, 1);
    }

    if (state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_DIRECTIONAL);
        objSetEventName(state->light, setupData->eventName);
        modelLightStruct_setDirection(state->light, vec.x, vec.y, vec.z);

        if ((setupData->flags & DIRECTIONALLIGHT_FLAG_USE_AMBIENT_COLOR) != 0)
        {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        }
        else
        {
            modelLightStruct_setDiffuseColor(state->light, setupData->diffuseR, setupData->diffuseG,
                                             setupData->diffuseB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, setupData->targetR, setupData->targetG,
                                                   setupData->targetB, 0xff);
        }

        modelLightStruct_setEnabled(state->light, setupData->enabled, lbl_803E7250);
        state->enabled = setupData->enabled;
        modelLightStruct_startColorFade(state->light, setupData->colorFadeSpeed, setupData->colorFadeFrames);

        if (setupData->selectionPriority != 0)
        {
            modelLightStruct_setSelectionPriority(state->light, setupData->selectionPriority);
        }
    }
}

void directionallight_release(void)
{
}

void directionallight_initialise(void)
{
}
