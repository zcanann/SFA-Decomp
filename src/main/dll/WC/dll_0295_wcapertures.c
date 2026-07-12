/*
 * wcapertures (DLL 0x295) - a glowing aperture / portal panel in the
 * Walled City (WC) that opens when the player frames it through a specific
 * camera. setup->armBit / openBit are game bits that persist and restore
 * state->mode across loads. state->mode: CLOSED waits for armBit; ARMED
 * waits until the camera mode and player state match, then fades the panel
 * to opaque, and if the FOV is tight enough and the object carries the
 * accept flag it sets openBit and goes OPEN. Alpha eases toward
 * state->targetAlpha each tick. A ModelLightStruct glow is created at init
 * and enabled while alpha is high; while OPEN, hitDetect spawns a partfx.
 * The ARM mode is also raised by interactCallback. Camera/player/partfx
 * numeric meanings are inferred.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/WC/dll_0295_wcapertures.h"
#include "main/dll/player_api.h"
#include "main/game_object.h"
#include "main/modellight_api.h"
#include "main/object_api.h"
#include "main/model.h"

#define WCAPERTURES_EXTRA_SIZE        8
#define WCAPERTURES_RENDER_TYPE_BASE  0x400
#define WCAPERTURES_RENDER_TYPE_SHIFT 0xb

#define WCAPERTURES_MODE_CLOSED 0
#define WCAPERTURES_MODE_ARMED  1
#define WCAPERTURES_MODE_OPEN   2

#define WCAPERTURES_FLAG_VISIBLE           1
#define WCAPERTURES_INITIAL_ALPHA          1
#define WCAPERTURES_ALPHA_OPAQUE           255
#define WCAPERTURES_ALPHA_STEP_SHIFT       2
#define WCAPERTURES_LIGHT_ENABLE_THRESHOLD 128

#define WCAPERTURES_CALLBACK_ARM 1

#define WCAPERTURES_PARTFX_OPEN           0x805
#define WCAPERTURES_PARTFX_KIND           2
#define WCAPERTURES_PARTFX_INVALID_HANDLE -1

#define WCAPERTURES_CAMERA_MODE        68
#define WCAPERTURES_PLAYER_STATE       33
#define WCAPERTURES_ACCEPT_OBJECT_FLAG 0x800

#define WCAPERTURES_LIGHT_KIND    2
#define WCAPERTURES_LIGHT_BLUE_LO 0x4d
#define WCAPERTURES_LIGHT_BLUE_HI 0x96

int wcapertures_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    WCAperturesState* state = obj->extra;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == WCAPERTURES_CALLBACK_ARM)
            state->mode = WCAPERTURES_MODE_ARMED;
    }
    return 0;
}

int wcapertures_getExtraSize(void)
{
    return WCAPERTURES_EXTRA_SIZE;
}

int wcapertures_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)&((WCAperturesSetup*)obj->anim.placementData)->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCAPERTURES_RENDER_TYPE_SHIFT) | WCAPERTURES_RENDER_TYPE_BASE;
}

void wcapertures_free(GameObject* obj)
{
    WCAperturesState* state = obj->extra;
    ModelLight* light = state->light;

    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
}

void wcapertures_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    WCAperturesState* state = (obj)->extra;
    ModelLight* light;

    if (visible != 0)
    {
        state->flags |= WCAPERTURES_FLAG_VISIBLE;
    }
    else
    {
        state->flags &= ~WCAPERTURES_FLAG_VISIBLE;
    }
    light = state->light;
    if (light != NULL && light->glowType != 0 && light->enabled != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6E2C);
    }
}

void wcapertures_hitDetect(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCAperturesState* state = obj->extra;

    if (state->mode == WCAPERTURES_MODE_OPEN)
    {
        s16 ev[18];
        f32 col[3];

        if (objAnim->bankIndex == 0)
            ev[1] = 1;
        else
            ev[1] = 0;
        col[0] = lbl_803E6E30;
        col[1] = lbl_803E6E34;
        col[2] = lbl_803E6E28;
        (*gPartfxInterface)
            ->spawnObject((void*)obj, WCAPERTURES_PARTFX_OPEN, ev, WCAPERTURES_PARTFX_KIND,
                          WCAPERTURES_PARTFX_INVALID_HANDLE, col);
    }
    if (state->light != NULL)
        modelLightStruct_updateGlowAlpha(state->light);
}

void wcapertures_update(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    WCAperturesSetup* setup = (WCAperturesSetup*)obj->anim.placementData;
    WCAperturesState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    ModelLight* light;
    int alpha, target;

    state->targetAlpha = 0;
    switch (state->mode)
    {
    case WCAPERTURES_MODE_OPEN:
        state->targetAlpha = 0;
        break;
    case WCAPERTURES_MODE_CLOSED:
        if ((u32)mainGetBit(setup->armBit) != 0)
        {
            state->mode = WCAPERTURES_MODE_ARMED;
        }
        break;
    case WCAPERTURES_MODE_ARMED:
        if ((*gCameraInterface)->getMode() == WCAPERTURES_CAMERA_MODE &&
            fn_802969F0(player) == WCAPERTURES_PLAYER_STATE)
        {
            state->targetAlpha = WCAPERTURES_ALPHA_OPAQUE;
            if (Camera_GetFovY() <= lbl_803E6E38 && (obj->objectFlags & WCAPERTURES_ACCEPT_OBJECT_FLAG))
            {
                mainSetBits(setup->openBit, 1);
                state->mode = WCAPERTURES_MODE_OPEN;
            }
        }
        break;
    }
    alpha = objAnim->alpha;
    target = state->targetAlpha;
    if (alpha < target)
    {
        int v = alpha + (framesThisStep << WCAPERTURES_ALPHA_STEP_SHIFT);
        if (v > target)
        {
            v = target;
        }
        objAnim->alpha = v;
    }
    else if (alpha > target)
    {
        int v = alpha - (framesThisStep << WCAPERTURES_ALPHA_STEP_SHIFT);
        if (v < target)
        {
            v = target;
        }
        objAnim->alpha = v;
    }
    light = state->light;
    if (light != NULL)
    {
        if (objAnim->alpha > WCAPERTURES_LIGHT_ENABLE_THRESHOLD)
        {
            modelLightStruct_setEnabled(light, 1, lbl_803E6E2C);
        }
        else
        {
            modelLightStruct_setEnabled(light, 0, lbl_803E6E2C);
        }
    }
}

void wcapertures_init(GameObject* obj, WCAperturesSetup* setup)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCAperturesState* state = (obj)->extra;

    (obj)->anim.rotX = (s16)(setup->type << 8);
    (obj)->animEventCallback = wcapertures_interactCallback;
    *(u8*)&objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
        objAnim->bankIndex = 0;
    if ((u32)mainGetBit(setup->armBit) != 0)
    {
        if ((u32)mainGetBit(setup->openBit) != 0)
            state->mode = WCAPERTURES_MODE_OPEN;
        else
            state->mode = WCAPERTURES_MODE_ARMED;
    }
    objAnim->alpha = WCAPERTURES_INITIAL_ALPHA;
    state->targetAlpha = WCAPERTURES_ALPHA_OPAQUE;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    state->light = objCreateLight(obj, 1);
    if (state->light != NULL)
    {
        modelLightStruct_setLightKind(state->light, WCAPERTURES_LIGHT_KIND);
        if (objAnim->bankIndex == 0)
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0xff, WCAPERTURES_LIGHT_BLUE_LO,
                                       WCAPERTURES_LIGHT_BLUE_HI, lbl_803E6E3C);
        else
            modelLightStruct_setupGlow(state->light, 0, WCAPERTURES_LIGHT_BLUE_LO, WCAPERTURES_LIGHT_BLUE_LO, 0xff,
                                       0xff, lbl_803E6E3C);
        modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E6E40);
    }
}

void wcapertures_release(void)
{
}

void wcapertures_initialise(void)
{
}
