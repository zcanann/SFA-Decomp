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
#include "main/game_object.h"

#define WCAPERTURES_EXTRA_SIZE 8
#define WCAPERTURES_RENDER_TYPE_BASE 0x400
#define WCAPERTURES_RENDER_TYPE_SHIFT 0xb

#define WCAPERTURES_SETUP_TYPE_OFFSET 0x18
#define WCAPERTURES_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCAPERTURES_SETUP_OPEN_BIT_OFFSET 0x1e
#define WCAPERTURES_SETUP_ARM_BIT_OFFSET 0x20

#define WCAPERTURES_STATE_LIGHT 0x00
#define WCAPERTURES_STATE_TARGET_ALPHA 0x04
#define WCAPERTURES_STATE_MODE 0x06
#define WCAPERTURES_STATE_FLAGS 0x07

#define WCAPERTURES_MODE_CLOSED 0
#define WCAPERTURES_MODE_ARMED 1
#define WCAPERTURES_MODE_OPEN 2

#define WCAPERTURES_FLAG_VISIBLE 1
#define WCAPERTURES_INITIAL_ALPHA 1
#define WCAPERTURES_ALPHA_OPAQUE 255
#define WCAPERTURES_ALPHA_STEP_SHIFT 2
#define WCAPERTURES_LIGHT_ENABLE_THRESHOLD 128

#define WCAPERTURES_CALLBACK_ARM 1

#define WCAPERTURES_PARTFX_OPEN 0x805
#define WCAPERTURES_PARTFX_KIND 2
#define WCAPERTURES_PARTFX_INVALID_HANDLE -1

#define WCAPERTURES_CAMERA_MODE 68
#define WCAPERTURES_PLAYER_STATE 33
#define WCAPERTURES_ACCEPT_OBJECT_FLAG 0x800

#define WCAPERTURES_LIGHT_KIND 2
#define WCAPERTURES_LIGHT_BLUE_LO 0x4d
#define WCAPERTURES_LIGHT_BLUE_HI 0x96

typedef struct WCAperturesSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[WCAPERTURES_SETUP_OPEN_BIT_OFFSET - 0x1A];
    s16 openBit;
    s16 armBit;
    u8 pad22[0x24 - 0x22];
} WCAperturesSetup;

typedef struct WCAperturesState
{
    void* light;
    s16 targetAlpha;
    u8 mode;
    u8 flags;
} WCAperturesState;

STATIC_ASSERT(sizeof(WCAperturesState) == WCAPERTURES_EXTRA_SIZE);
STATIC_ASSERT(sizeof(WCAperturesSetup) == 0x24);
STATIC_ASSERT(offsetof(WCAperturesState, light) == WCAPERTURES_STATE_LIGHT);
STATIC_ASSERT(offsetof(WCAperturesState, targetAlpha) == WCAPERTURES_STATE_TARGET_ALPHA);
STATIC_ASSERT(offsetof(WCAperturesState, mode) == WCAPERTURES_STATE_MODE);
STATIC_ASSERT(offsetof(WCAperturesState, flags) == WCAPERTURES_STATE_FLAGS);
STATIC_ASSERT(offsetof(WCAperturesSetup, type) == WCAPERTURES_SETUP_TYPE_OFFSET);
STATIC_ASSERT(offsetof(WCAperturesSetup, modelIndex) == WCAPERTURES_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCAperturesSetup, openBit) == WCAPERTURES_SETUP_OPEN_BIT_OFFSET);
STATIC_ASSERT(offsetof(WCAperturesSetup, armBit) == WCAPERTURES_SETUP_ARM_BIT_OFFSET);

int wcapertures_getExtraSize(void) { return WCAPERTURES_EXTRA_SIZE; }

int wcapertures_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)&((WCAperturesSetup*)((GameObject*)obj)->anim.placementData)->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCAPERTURES_RENDER_TYPE_SHIFT) | WCAPERTURES_RENDER_TYPE_BASE;
}

void wcapertures_free(int obj)
{
    WCAperturesState* state = ((GameObject*)obj)->extra;
    void* light = state->light;

    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
}

void wcapertures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    WCAperturesState* state = ((GameObject*)obj)->extra;
    u8* light;

    if (visible != 0)
    {
        state->flags |= WCAPERTURES_FLAG_VISIBLE;
    }
    else
    {
        state->flags &= ~WCAPERTURES_FLAG_VISIBLE;
    }
    light = state->light;
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6E2C);
    }
}

void wcapertures_hitDetect(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCAperturesState* state = ((GameObject*)obj)->extra;

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
        (*gPartfxInterface)->spawnObject((void*)obj, WCAPERTURES_PARTFX_OPEN, ev,
                                         WCAPERTURES_PARTFX_KIND,
                                         WCAPERTURES_PARTFX_INVALID_HANDLE, col);
    }
    if (state->light != NULL)
        modelLightStruct_updateGlowAlpha(state->light);
}

void wcapertures_release(void)
{
}

void wcapertures_initialise(void)
{
}

int wcapertures_interactCallback(int obj, int p2, ObjAnimUpdateState* animUpdate)
{
    int i;
    WCAperturesState* state = ((GameObject*)obj)->extra;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == WCAPERTURES_CALLBACK_ARM)
            state->mode = WCAPERTURES_MODE_ARMED;
    }
    return 0;
}

void wcapertures_init(int obj, int initData)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCAperturesState* state = ((GameObject*)obj)->extra;
    WCAperturesSetup* setup = (WCAperturesSetup*)initData;

    ((GameObject*)obj)->anim.rotX = (s16)(setup->type << 8);
    ((GameObject*)obj)->animEventCallback = wcapertures_interactCallback;
    *(u8*)&objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
        objAnim->bankIndex = 0;
    if ((u32)GameBit_Get(setup->armBit) != 0)
    {
        if ((u32)GameBit_Get(setup->openBit) != 0)
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
            modelLightStruct_setupGlow(state->light, 0, WCAPERTURES_LIGHT_BLUE_LO,
                                       WCAPERTURES_LIGHT_BLUE_LO, 0xff, 0xff, lbl_803E6E3C);
        modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E6E40);
    }
}

void wcapertures_update(int obj)
{
    ObjAnimComponent* objAnim = &((GameObject*)obj)->anim;
    WCAperturesSetup* setup = (WCAperturesSetup*)((GameObject*)obj)->anim.placementData;
    WCAperturesState* state = ((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();
    void* light;
    int alpha, target;

    state->targetAlpha = 0;
    switch (state->mode)
    {
    case WCAPERTURES_MODE_OPEN:
        state->targetAlpha = 0;
        break;
    case WCAPERTURES_MODE_CLOSED:
        if ((u32)GameBit_Get(setup->armBit) != 0)
        {
            state->mode = WCAPERTURES_MODE_ARMED;
        }
        break;
    case WCAPERTURES_MODE_ARMED:
        if ((*gCameraInterface)->getMode() == WCAPERTURES_CAMERA_MODE &&
            fn_802969F0(player) == WCAPERTURES_PLAYER_STATE)
        {
            state->targetAlpha = WCAPERTURES_ALPHA_OPAQUE;
            if (Camera_GetFovY() <= lbl_803E6E38 && (((GameObject*)obj)->objectFlags & WCAPERTURES_ACCEPT_OBJECT_FLAG))
            {
                GameBit_Set(setup->openBit, 1);
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
