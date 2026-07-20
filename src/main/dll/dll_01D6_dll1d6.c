/* DLL 0x1D6 - DIM2 crusher platform [801B63F4-801B6464) */
#include "main/dll/dimmagicbridge_state.h"
#include "main/object_api.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/dll_01D6_dll1d6.h"
#include "main/dll/explosion_state.h"
#include "main/objtexture.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/asset_load.h"
#include "main/pi_dolphin.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

s16 gDll1D6SlotTabIndex[4] = {0x10A, 0x14F, 0x151, 0x153};
u8 gDll1D6SlotInUse[8] = {0};

/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* DIM2PathGenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

#define DLL1D6_ACTION_SLOT_COUNT    4
#define DLL1D6_ACTION_DATA_SIZE     40
#define DLL1D6_HIT_ENABLE_GAMEBIT   496

FbWGPipe GXWGFifo : (0xCC008000);

int dll_1D6_getExtraSize(void)
{
    return 0x20;
}

int dll_1D6_getObjectTypeId(void)
{
    return 0x0;
}

void dll_1D6_free(GameObject* obj)
{
    Dll1D6State* state = obj->extra;
    if ((state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) != 0)
    {
        state->flags = (u8)(state->flags & ~DLL1D6_STATE_FLAG_BOB_ACTIVE);
    }
    mm_free(state->actionDataA);
    mm_free(state->actionDataB);
    gDll1D6SlotInUse[state->actionSlot] = 0;
}

void dll_1D6_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dll_1D6_hitDetect(void)
{
}

static inline ObjModel* Dll1D6_GetActiveModel(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

void dll_1D6_update(GameObject* obj)
{
    Dll1D6State* state;
    Dll1D6Placement* placement;
    ObjModel* model;
    ObjTextureRuntimeSlot* tex;
    GameObject* player;
    f32 mtx[20];
    s16 ang[6];
    f32 lx, ly, lz;

    placement = (Dll1D6Placement*)obj->anim.placementData;
    state = obj->extra;

    if ((state->flags & DLL1D6_STATE_FLAG_DOWN_PHASE) != 0)
    {
        if ((state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) == 0)
        {
            state->flags |= DLL1D6_STATE_FLAG_BOB_ACTIVE;
            state->bobPhase = (f32)(int)randomGetRange(20, 40);
            state->bobRate = (f32)(int)randomGetRange(6, 10) / 20.0f;
        }
        state->downTimer -= framesThisStep;
        state->dizzyTimer = state->dizzyTimer - framesThisStep;
        if (state->dizzyTimer <= 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_en_trpopn_c_9f);
        }
        if (state->downTimer <= 0)
        {
            model = Dll1D6_GetActiveModel(obj);
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.1f, 16);
            state->upTimer = placement->upTimer;
            if (state->upTimer < 15)
            {
                state->upTimer = 15;
            }
            state->flags &= ~DLL1D6_STATE_FLAG_DOWN_PHASE;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_1f6);
        }
    }
    else
    {
        ObjModelBlendChannel* blendChannel;
        model = Dll1D6_GetActiveModel(obj);
        blendChannel = model->blendChannels;
        if (blendChannel != NULL && (state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) != 0)
        {
            if (blendChannel->weight >= 1.0f)
            {
                state->flags &= ~DLL1D6_STATE_FLAG_BOB_ACTIVE;
            }
        }
        state->upTimer -= framesThisStep;
        if (state->upTimer <= 0)
        {
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, -0.1f, 16);
            state->downTimer = placement->downTimer;
            if (state->downTimer < 15)
            {
                state->downTimer = 15;
            }
            state->flags |= DLL1D6_STATE_FLAG_DOWN_PHASE;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_1f7);
            state->dizzyTimer = 20;
        }
    }
    tex = objFindTexture((GameObject*)(obj), 0, 0);
    {
        s16 t = -tex->offsetT;
        int v = t + 256;
        if ((s16)v > 2048)
        {
            v = v - 2048;
        }
        tex->offsetT = -v;
    }
    tex = objFindTexture((GameObject*)(obj), 1, 0);
    {
        s16 t = -tex->offsetT;
        int v = t + 160;
        if ((s16)v > 2048)
        {
            v = v - 2048;
        }
        tex->offsetT = -v;
    }
    player = Obj_GetPlayerObject();
    mtx[0] = -obj->anim.localPosX;
    mtx[1] = -obj->anim.localPosY;
    mtx[2] = -obj->anim.localPosZ;
    ang[0] = -obj->anim.rotX;
    ang[1] = 0;
    ang[2] = 0;
    mtxRotateByVec3s(&mtx[3], ang);
    Matrix_TransformPoint(&mtx[3], player->anim.localPosX, player->anim.localPosY, player->anim.localPosZ, &lx, &ly,
                          &lz);
    if ((state->flags & DLL1D6_STATE_FLAG_HIT_ENABLED) != 0)
    {
        ly = obj->anim.localPosY - player->anim.localPosY;
        if (ly < 0.0f)
        {
            ly = -ly;
        }
        if (ly < 50.0f)
        {
            lz = lz * lz;
            if (lz <= state->hitRangeSqA)
            {
                int* row;
                f32 lim;
                model = Dll1D6_GetActiveModel(obj);
                {
                    char* mrow = (char*)model + 4;
                    row = *(int**)(mrow + ((((ObjModel*)model)->bufferFlags >> 1) & 1) * 4);
                }
                lim = obj->anim.rootMotionScale * (f32)(int)*(s16*)((char*)row + state->hitRow * 16);
                if (lx <= lim)
                {
                    ObjHits_RecordObjectHit(player, obj, 11, 4, 0);
                }
            }
        }
    }
    if ((state->flags & DLL1D6_STATE_FLAG_BOB_ACTIVE) != 0)
    {
        state->bobPhase = state->bobRate * timeDelta + state->bobPhase;
        if (state->bobPhase > 40.0f)
        {
            state->bobRate = -(f32)(int)randomGetRange(6, 10) / 20.0f;
            state->bobPhase = 40.0f;
        }
        else if (state->bobPhase < 20.0f)
        {
            state->bobRate = (f32)(int)randomGetRange(6, 10) / 20.0f;
            state->bobPhase = 20.0f;
        }
    }
    if (mainGetBit(DLL1D6_HIT_ENABLE_GAMEBIT) != 0)
    {
        state->flags |= DLL1D6_STATE_FLAG_HIT_ENABLED;
    }
    else
    {
        state->flags &= ~DLL1D6_STATE_FLAG_HIT_ENABLED;
    }
}

void dll_1D6_init(GameObject* obj, Dll1D6Placement* placement)
{
    Dll1D6State* state;
    ObjModel* model;
    int i;

    obj->anim.rotX = (s16)(placement->rotX << 8);
    state = obj->extra;
    model = Dll1D6_GetActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.0f, 0);
    ObjModel_SetBlendChannelWeight(model, 0, 1.0f);
    state->upTimer = placement->upTimer;
    if (state->upTimer < 15)
    {
        state->upTimer = 15;
    }
    state->downTimer = placement->downTimer;
    if (state->downTimer < 15)
    {
        state->downTimer = 15;
    }
    {
        f32 k = 0.0f;
        state->hitRangeSqA = k * obj->anim.rootMotionScale;
        state->hitRangeSqA = state->hitRangeSqA * state->hitRangeSqA;
        state->hitRangeSqB = k * obj->anim.rootMotionScale;
        state->hitRangeSqB = state->hitRangeSqB * state->hitRangeSqB;
    }
    state->flags = mainGetBit(DLL1D6_HIT_ENABLE_GAMEBIT) ? DLL1D6_STATE_FLAG_HIT_ENABLED : 0;
    for (i = 0; i < DLL1D6_ACTION_SLOT_COUNT; i++)
    {
        if ((gDll1D6SlotInUse)[i] == 0)
        {
            (gDll1D6SlotInUse)[i] = 1;
            state->actionSlot = i;
            i = DLL1D6_ACTION_SLOT_COUNT;
        }
    }
    state->actionDataA = mmAlloc(DLL1D6_ACTION_DATA_SIZE, 18, 0);
    getTabEntry(state->actionDataA, MLDF_FILEID_LACTIONS_BIN,
                gDll1D6SlotTabIndex[state->actionSlot] * DLL1D6_ACTION_DATA_SIZE, DLL1D6_ACTION_DATA_SIZE);
    state->actionDataB = mmAlloc(DLL1D6_ACTION_DATA_SIZE, 18, 0);
    getTabEntry(state->actionDataB, MLDF_FILEID_LACTIONS_BIN,
                (gDll1D6SlotTabIndex[state->actionSlot] + 1) * DLL1D6_ACTION_DATA_SIZE, DLL1D6_ACTION_DATA_SIZE);
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1D6_release(void)
{
}

void dll_1D6_initialise(void)
{
}

ObjectDescriptor dll_1D6 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1D6_initialise,
    (ObjectDescriptorCallback)dll_1D6_release,
    0,
    (ObjectDescriptorCallback)dll_1D6_init,
    (ObjectDescriptorCallback)dll_1D6_update,
    (ObjectDescriptorCallback)dll_1D6_hitDetect,
    (ObjectDescriptorCallback)dll_1D6_render,
    (ObjectDescriptorCallback)dll_1D6_free,
    (ObjectDescriptorCallback)dll_1D6_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_1D6_getExtraSize,
};
