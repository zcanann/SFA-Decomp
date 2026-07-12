/*
 * wctemplebri (DLL 0x297) - a temple bridge in the Walled City (WC) that
 * materializes when triggered. While active it fades alpha up to opaque,
 * latches FLAG_SOLVED, sets its placement solvedBit and enables collision;
 * while inactive it fades out and disables collision. Each frame it scrolls
 * two texture layers (wrapping at the warp limit) and advances two wave
 * phase accumulators, then runs a per-vertex sine deformation that pushes
 * each vertex by a wave indexed on its height. A global "bridge active"
 * game bit is set/cleared from update and also cleared when the player is
 * beyond a threshold distance. Two model variants select the render type
 * id. Some init bookkeeping (the sortedOffsets sort, partFlags/partAlpha
 * arrays) appears only partly wired; behavior is inferred.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/model.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/WC/dll_0297_wctemplebri.h"

#define WCTEMPLEBRI_EXTRA_SIZE        0x68
#define WCTEMPLEBRI_RENDER_TYPE_BASE  0x400
#define WCTEMPLEBRI_RENDER_TYPE_SHIFT 0xb

#define WCTEMPLEBRI_SETUP_TYPE_OFFSET        0x18
#define WCTEMPLEBRI_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET  0x1e

#define WCTEMPLEBRI_STATE_MAX_Y          0x00
#define WCTEMPLEBRI_STATE_SORTED_OFFSETS 0x04
#define WCTEMPLEBRI_STATE_PART_FLAGS     0x40
#define WCTEMPLEBRI_STATE_PART_COUNT     0x4f
#define WCTEMPLEBRI_STATE_PART_ALPHA     0x50
#define WCTEMPLEBRI_STATE_ACTIVE         0x5f
#define WCTEMPLEBRI_STATE_WAVE_PHASE_A   0x60
#define WCTEMPLEBRI_STATE_WAVE_PHASE_B   0x62
#define WCTEMPLEBRI_STATE_FLAGS          0x66

#define WCTEMPLEBRI_FLAG_SOLVED       1
#define WCTEMPLEBRI_GLOBAL_ACTIVE_BIT 0xedb

#define WCTEMPLEBRI_PAYLOAD_TRIGGER    1
#define WCTEMPLEBRI_PAYLOAD_BLOCK_FLAG 0x20

#define WCTEMPLEBRI_ALPHA_OPAQUE      0xff
#define WCTEMPLEBRI_WARP_WRAP         0x2710
#define WCTEMPLEBRI_UV0_V_STEP        0x14
#define WCTEMPLEBRI_UV0_U_STEP        0xa
#define WCTEMPLEBRI_UV1_V_STEP        0x1e
#define WCTEMPLEBRI_WAVE_A_STEP_SHIFT 8
#define WCTEMPLEBRI_WAVE_B_STEP_SHIFT 7
#define WCTEMPLEBRI_WAVE_WRAP         0xffff

#define WCTEMPLEBRI_OBJFLAG_HIDDEN             0x4000
#define WCTEMPLEBRI_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct WCTempleBriSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET - 0x1A];
    s16 solvedBit;
    u8 pad20[0x24 - 0x20];
} WCTempleBriSetup;

typedef struct WCTempleBriState
{
    f32 maxY;
    f32 sortedOffsets[15];
    u8 partFlags[15];
    u8 partCount;
    u8 partAlpha[15];
    u8 active;
    u16 wavePhaseA;
    u16 wavePhaseB;
    u8 pad64[WCTEMPLEBRI_STATE_FLAGS - 0x64];
    u8 flags;
    u8 pad67;
} WCTempleBriState;

STATIC_ASSERT(sizeof(WCTempleBriState) == WCTEMPLEBRI_EXTRA_SIZE);
STATIC_ASSERT(sizeof(WCTempleBriSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTempleBriState, maxY) == WCTEMPLEBRI_STATE_MAX_Y);
STATIC_ASSERT(offsetof(WCTempleBriState, sortedOffsets) == WCTEMPLEBRI_STATE_SORTED_OFFSETS);
STATIC_ASSERT(offsetof(WCTempleBriState, partFlags) == WCTEMPLEBRI_STATE_PART_FLAGS);
STATIC_ASSERT(offsetof(WCTempleBriState, partCount) == WCTEMPLEBRI_STATE_PART_COUNT);
STATIC_ASSERT(offsetof(WCTempleBriState, partAlpha) == WCTEMPLEBRI_STATE_PART_ALPHA);
STATIC_ASSERT(offsetof(WCTempleBriState, active) == WCTEMPLEBRI_STATE_ACTIVE);
STATIC_ASSERT(offsetof(WCTempleBriState, wavePhaseA) == WCTEMPLEBRI_STATE_WAVE_PHASE_A);
STATIC_ASSERT(offsetof(WCTempleBriState, wavePhaseB) == WCTEMPLEBRI_STATE_WAVE_PHASE_B);
STATIC_ASSERT(offsetof(WCTempleBriState, flags) == WCTEMPLEBRI_STATE_FLAGS);
STATIC_ASSERT(offsetof(WCTempleBriSetup, type) == WCTEMPLEBRI_SETUP_TYPE_OFFSET);
STATIC_ASSERT(offsetof(WCTempleBriSetup, modelIndex) == WCTEMPLEBRI_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCTempleBriSetup, solvedBit) == WCTEMPLEBRI_SETUP_SOLVED_BIT_OFFSET);

void wctemplebri_updateModelWarp(GameObject* obj, int p2)
{
    WCTempleBriState* state = (WCTempleBriState*)p2;
    ObjTextureRuntimeSlot* tex;
    int phase;

    tex = objFindTexture(obj, 0, 0);
    tex->offsetT += WCTEMPLEBRI_UV0_V_STEP;
    if (tex->offsetT > WCTEMPLEBRI_WARP_WRAP)
        tex->offsetT -= WCTEMPLEBRI_WARP_WRAP;
    tex->offsetS += WCTEMPLEBRI_UV0_U_STEP;
    if (tex->offsetS > WCTEMPLEBRI_WARP_WRAP)
        tex->offsetS -= WCTEMPLEBRI_WARP_WRAP;
    tex = objFindTexture(obj, 1, 0);
    tex->offsetT += WCTEMPLEBRI_UV1_V_STEP;
    if (tex->offsetT > WCTEMPLEBRI_WARP_WRAP)
        tex->offsetT -= WCTEMPLEBRI_WARP_WRAP;
    phase = state->wavePhaseA + (framesThisStep << WCTEMPLEBRI_WAVE_A_STEP_SHIFT);
    if (phase > WCTEMPLEBRI_WAVE_WRAP)
        phase = (phase - 0x10000) + 1;
    state->wavePhaseA = phase;
    phase = state->wavePhaseB + (framesThisStep << WCTEMPLEBRI_WAVE_B_STEP_SHIFT);
    if (phase > WCTEMPLEBRI_WAVE_WRAP)
        phase = (phase - 0x10000) + 1;
    state->wavePhaseB = phase;
}

int wctemplebri_SeqFn(GameObject* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    ObjAnimComponent* objAnim = &obj->anim;
    WCTempleBriSetup* setup = (WCTempleBriSetup*)obj->anim.placementData;
    ObjModel* model;
    ModelFileHeader* modelBase;
    int i;
    f32 waveScale;
    WCTempleBriState* state = obj->extra;

    animUpdate->sequenceEventActive = 0;
    animUpdate->activeHitVolumePair &= ~WCTEMPLEBRI_PAYLOAD_BLOCK_FLAG;
    animUpdate->hitVolumePair &= ~WCTEMPLEBRI_PAYLOAD_BLOCK_FLAG;
    wctemplebri_updateModelWarp(obj, (int)state);
    if (animUpdate->triggerCommand == WCTEMPLEBRI_PAYLOAD_TRIGGER)
    {
        state->active = 1;
    }
    if (state->active != 0)
    {
        if ((state->flags & WCTEMPLEBRI_FLAG_SOLVED) == 0)
        {
            state->flags |= WCTEMPLEBRI_FLAG_SOLVED;
            mainSetBits(setup->solvedBit, 1);
        }
        {
            int a = (int)((f32)(u32)objAnim->alpha + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > WCTEMPLEBRI_ALPHA_OPAQUE)
                a = WCTEMPLEBRI_ALPHA_OPAQUE;
            objAnim->alpha = a;
        }
    }
    model = Obj_GetActiveModel(obj);
    modelBase = model->file;
    i = 0;
    waveScale = *(f32*)&lbl_803E6E70;
    for (; i < modelBase->vertexCount; i++)
    {
        s16* curr = ObjModel_GetCurrentVertexCoords(model, i);
        s16* base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int wave = (u16)(int)(waveScale * ((f32)curr[2] / state->maxY));
        int idx = wave + state->wavePhaseA;
        if (base[0] > 0)
            curr[0] = (s16)(lbl_803E6E74 * mathSinf(lbl_803E6E78 * idx / lbl_803E6E7C) + (f32)base[0]);
        else
            curr[0] = (s16)((f32)base[0] - lbl_803E6E74 * mathSinf(lbl_803E6E78 * idx / lbl_803E6E7C));
    }
    return 0;
}

int wctemplebri_getExtraSize(void)
{
    return WCTEMPLEBRI_EXTRA_SIZE;
}

int wctemplebri_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)&((WCTempleBriSetup*)obj->anim.placementData)->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCTEMPLEBRI_RENDER_TYPE_SHIFT) | WCTEMPLEBRI_RENDER_TYPE_BASE;
}

void wctemplebri_free(void)
{
}

void wctemplebri_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    WCTempleBriState* state = (obj)->extra;

    if (visible == 0 || state->active == 0)
    {
        return;
    }

    objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6E90);
}

void wctemplebri_hitDetect(void)
{
}

void wctemplebri_release(void)
{
}

void wctemplebri_initialise(void)
{
}

void wctemplebri_update(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ObjModel* model;
    ModelFileHeader* modelBase;
    int i;
    f32 waveScale;
    WCTempleBriState* state;
    WCTempleBriSetup* setup = (WCTempleBriSetup*)obj->anim.placementData;

    Obj_GetPlayerObject();
    state = obj->extra;
    wctemplebri_updateModelWarp(obj, (int)state);
    model = Obj_GetActiveModel(obj);
    modelBase = model->file;
    i = 0;
    waveScale = *(f32*)&lbl_803E6E70;
    for (; i < modelBase->vertexCount; i++)
    {
        s16* curr = ObjModel_GetCurrentVertexCoords(model, i);
        s16* base = ObjModel_GetBaseVertexCoords(modelBase, i);
        int wave = (u16)(int)(waveScale * ((f32)curr[2] / state->maxY));
        int idx = wave + state->wavePhaseA;
        if (base[0] > 0)
            curr[0] = (s16)(lbl_803E6E74 * mathSinf(lbl_803E6E78 * idx / lbl_803E6E7C) + (f32)base[0]);
        else
            curr[0] = (s16)((f32)base[0] - lbl_803E6E74 * mathSinf(lbl_803E6E78 * idx / lbl_803E6E7C));
    }
    if (state->active != 0)
    {
        if ((state->flags & WCTEMPLEBRI_FLAG_SOLVED) == 0)
        {
            mainSetBits(WCTEMPLEBRI_GLOBAL_ACTIVE_BIT, 1);
            state->flags |= WCTEMPLEBRI_FLAG_SOLVED;
            mainSetBits(setup->solvedBit, 1);
        }
        {
            int a = (int)((f32)(u32)objAnim->alpha + timeDelta);
            if (a < 0)
                a = 0;
            else if (a > WCTEMPLEBRI_ALPHA_OPAQUE)
                a = WCTEMPLEBRI_ALPHA_OPAQUE;
            objAnim->alpha = a;
        }
        ObjHits_EnableObject((u32)obj);
    }
    else
    {
        mainSetBits(WCTEMPLEBRI_GLOBAL_ACTIVE_BIT, 0);
        ObjHits_DisableObject((u32)obj);
    }
    if ((void*)Obj_GetPlayerObject() != NULL)
    {
        if (PSVECDistance((void*)&obj->anim.worldPosX,
                          &((GameObject*)Obj_GetPlayerObject())->anim.worldPosX) > lbl_803E6E94)
        {
            mainSetBits(WCTEMPLEBRI_GLOBAL_ACTIVE_BIT, 0);
        }
    }
}

void wctemplebri_init(GameObject* obj, int initData)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCTempleBriState* state;
    WCTempleBriSetup* setup = (WCTempleBriSetup*)initData;
    ObjModel* model;
    int i;
    int maxY;
    ModelFileHeader* modelData;
    int k;
    int done;

    obj->anim.rotX = (s16)(setup->type << 8);
    *(u8*)&objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
        objAnim->bankIndex = 0;
    obj->animEventCallback = wctemplebri_SeqFn;
    state = obj->extra;
    maxY = 0;
    model = Obj_GetActiveModel(obj);
    modelData = model->file;
    for (i = 0; i < modelData->vertexCount; i++)
    {
        int y = ObjModel_GetCurrentVertexCoords(model, i)[2];
        if (y < maxY)
            maxY = y;
    }
    done = 0;
    while (done == 0)
    {
        done = 1;
        for (k = 0; k < state->partCount - 1; k++)
        {
            f32 a = state->sortedOffsets[k];
            f32 b = state->sortedOffsets[k + 1];
            if (a < b)
            {
                state->sortedOffsets[k] = b;
                state->sortedOffsets[k + 1] = (f32)(int)a;
                done = 0;
            }
        }
    }
    state->partCount = 0xa;
    state->maxY = maxY;
    if ((u32)mainGetBit(setup->solvedBit) != 0)
    {
        state->active = 1;
        state->flags |= WCTEMPLEBRI_FLAG_SOLVED;
    }
    if (state->active != 0)
    {
        for (k = 0; k < state->partCount; k++)
        {
            state->partAlpha[k] = WCTEMPLEBRI_ALPHA_OPAQUE;
            state->partFlags[k] = 1;
        }
        objAnim->alpha = WCTEMPLEBRI_ALPHA_OPAQUE;
    }
    else
    {
        ObjHits_DisableObject((u32)obj);
        objAnim->alpha = 0;
    }
    obj->objectFlags |= (WCTEMPLEBRI_OBJFLAG_HIDDEN | WCTEMPLEBRI_OBJFLAG_HITDETECT_DISABLED);
    ObjModel_SetPostRenderCallback(model, postRenderSetAlphaBlendState);
}
