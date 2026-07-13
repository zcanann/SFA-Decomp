/* DLL 0x19E — DIM Tricky companion object: sparkle effect, hit-detect toggle,
 * line-of-sight voxmap trace, and Tricky egg-interact sequence trigger. */
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/audio/sfx_ids.h"
#include "main/gameplay_runtime.h"
#include "main/obj_placement.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/camera.h"
#include "main/gamebits.h"
#include "main/dll/DR/dr_802bbc10_shared.h"



__declspec(section ".sdata2") f32 gDimTrickyLosMinDist = 50.0f;
__declspec(section ".sdata2") f32 lbl_803E51CC = 1.0f;
__declspec(section ".sdata2") f32 gDimTrickyLosObjOffsetDist = 32.0f;
__declspec(section ".sdata2") f32 gDimTrickyLosCamOffsetDist = -20.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E51D8 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E51DC = 5.0f;
__declspec(section ".sdata2") f32 lbl_803E51E0 = -2.0f;
__declspec(section ".sdata2") f32 gDimTrickyScaleTimerDivisor = 8192.0f;
__declspec(section ".sdata2") f32 lbl_803E51E8 = 0.1f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E51EC = 0.0f;
#pragma explicit_zero_data off
extern s8 gDimTrickyEggSequenceStage;
extern u32 gDimTrickyEggResArgsTemplate[4];

/* Partfx: idle sparkle emitted in render while the object is visible (losVisible);
 * the egg-activation burst emitted 100x in update when the egg turns active. */
#define DIMTRICKY_PARTFX_IDLE_SPARKLE 0x1f7
#define DIMTRICKY_PARTFX_EGG_ACTIVATE 0x1a3

int dll_19E_getExtraSize(void) { return 0x10; }
int dll_19E_getObjectTypeId(void) { return 0x1; }

void dll_19E_free(GameObject *obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

typedef struct Dll19EState
{
    s32 gameBitId;
    s16 delayTimer;
    s16 resetTimer;
    s16 settleTimer;
    u8 losVisible; /* line-of-sight voxmap trace result: 1=visible, 0=blocked */
    u8 mode;
    u8 active;
    u8 needsOpenSfx;
    u8 previousActive;
    u8 sequenceIndex;
} Dll19EState;

enum DimTrickyMode
{
    DIM_TRICKY_MODE_SPARKLE = 0,     /* autonomous sparkle/egg effect spawner */
    DIM_TRICKY_MODE_EGG_INTERACT = 1 /* hit-detect toggle egg-interact sequence */
};

void dll_19E_render(GameObject *obj, int p2, int p3, int p4,
                    int p5, s8 visible)
{
    Dll19EState* state;
    CameraViewSlot* camera;
    f32 dist;
    f32 invDist;
    f32 facz, facy, facx;
    f32 facz2, facy2, facx2;
    f32 nz, ny, nx;
    struct
    {
        f32 delta[3];

        struct
        {
            u8 pad[0xc];
            f32 x, y, z;
        } args;
    } stk;
    f32 midA[3];
    f32 midB[3];
    f32 gridA[2];
    f32 gridB[2];
    int traceOut[2];

    state = (obj)->extra;
    if (visible == 0)
    {
        state->delayTimer = 0;
        state->losVisible = 0;
    }
    else if (state->active != 0)
    {
        state->losVisible = 1;
        camera = Camera_GetCurrentViewSlot();
        stk.delta[0] = camera->x - (obj)->anim.localPosX;
        stk.delta[1] = camera->y - (obj)->anim.localPosY;
        stk.delta[2] = camera->z - (obj)->anim.localPosZ;
        dist = sqrtf(stk.delta[2] * stk.delta[2] + (stk.delta[0] * stk.delta[0] + stk.delta[1] * stk.delta[1]));
        if (dist > gDimTrickyLosMinDist)
        {
            invDist = lbl_803E51CC / dist;
            nx = stk.delta[0] * invDist;
            stk.delta[0] = nx;
            ny = stk.delta[1] * invDist;
            stk.delta[1] = ny;
            nz = stk.delta[2] * invDist;
            stk.delta[2] = nz;
            facx = gDimTrickyLosObjOffsetDist * nx;
            midA[0] = facx;
            facy = gDimTrickyLosObjOffsetDist * ny;
            midA[1] = facy;
            facz = gDimTrickyLosObjOffsetDist * nz;
            midA[2] = facz;
            midA[0] = facx + (obj)->anim.localPosX;
            midA[1] = facy + (obj)->anim.localPosY;
            midA[2] = facz + (obj)->anim.localPosZ;
            facx2 = gDimTrickyLosCamOffsetDist * nx;
            midB[0] = facx2;
            facy2 = gDimTrickyLosCamOffsetDist * ny;
            midB[1] = facy2;
            facz2 = gDimTrickyLosCamOffsetDist * nz;
            midB[2] = facz2;
            midB[0] = facx2 + camera->x;
            midB[1] = facy2 + camera->y;
            midB[2] = facz2 + camera->z;
            voxmaps_worldToGrid(midA, (s16*)gridA);
            voxmaps_worldToGrid(midB, (s16*)gridB);
            if (voxmaps_traceLine((VoxPos*)gridA, (VoxPos*)gridB, (VoxPos*)traceOut, NULL, 0) == 0)
            {
                state->losVisible = 0;
                (*gExpgfxInterface)->freeSource((int)obj);
            }
        }
        if (state->delayTimer > 0)
        {
            state->delayTimer -= framesThisStep;
        }
        else
        {
            if (state->losVisible != 0)
            {
                stk.args.x = lbl_803E51D8;
                stk.args.y = lbl_803E51DC;
                stk.args.z = lbl_803E51D8;
                (*gPartfxInterface)->spawnObject((void*)obj, DIMTRICKY_PARTFX_IDLE_SPARKLE, &stk.args, 0x12, -1, NULL);
            }
            state->delayTimer = (s16)(randomGetRange(-10, 10) + 0x3c);
        }
    }
}

void dll_19E_hitDetect(void)
{
}

typedef struct Dll19ESetup
{
    ObjPlacement base;
    s8 objectType;
    u8 mode;
    s16 scaleTimer;
    s16 sequenceIndex;
    s16 gameBitId;
} Dll19ESetup;

STATIC_ASSERT(sizeof(Dll19ESetup) == 0x20);
STATIC_ASSERT(offsetof(Dll19ESetup, objectType) == 0x18);
STATIC_ASSERT(offsetof(Dll19ESetup, mode) == 0x19);
STATIC_ASSERT(offsetof(Dll19ESetup, scaleTimer) == 0x1A);
STATIC_ASSERT(offsetof(Dll19ESetup, sequenceIndex) == 0x1C);
STATIC_ASSERT(offsetof(Dll19ESetup, gameBitId) == 0x1E);

typedef struct Dll19EResArgs
{
    u32 a;
    u32 b;
    u32 c;
    u32 d;
} Dll19EResArgs;

#define TRICKY_EGG_EFFECT_RESOURCE_ID  0x69
#define GAMEBIT_TRICKY_EGG_SEQUENCE_DONE  0x1d1
#define GAMEBIT_TRICKY_EGG_CUTSCENE_DONE  0x1d5

void dll_19E_update(void* obj)
{

    Dll19EState* state;
    void* resource;
    struct
    {
        u8 args[16];
        f32 scale;
    } effectBuf;
    u32 resourceArgs[4];
    int i;

    state = ((GameObject*)obj)->extra;
    *(Dll19EResArgs*)resourceArgs = *(Dll19EResArgs*)gDimTrickyEggResArgsTemplate;

    ((void (*)(void*, int))Sfx_PlayFromObject)(obj, SFXmn_eggylaugh216);
    objUpdateOpacity((GameObject*)obj);
    if (state->settleTimer > 0)
    {
        state->settleTimer -= framesThisStep;
    }

    if (state->mode == DIM_TRICKY_MODE_EGG_INTERACT)
    {
        effectBuf.scale = lbl_803E51E0;
        state->previousActive = state->active;
        if ((ObjHits_GetPriorityHit((GameObject*)(obj), 0, 0, 0) != 0) ||
            ((state->settleTimer != 0) && (state->settleTimer <= 0x14)))
        {
            state->active = (u8)(1 - state->active);
            if (state->active != 0)
            {
                state->resetTimer = 1000;
            }
            if (state->settleTimer != 0)
            {
                state->settleTimer = 0;
                gDimTrickyEggSequenceStage = 3;
                state->resetTimer = 300;
                if (state->sequenceIndex == 2)
                {
                    mainSetBits(GAMEBIT_TRICKY_EGG_SEQUENCE_DONE, 1);
                }
            }
        }

        if ((state->active != 0) && (state->resetTimer != 0))
        {
            state->resetTimer -= framesThisStep;
            if (state->resetTimer <= 0)
            {
                state->resetTimer = 0;
                state->active = 0;
            }
        }

        if ((state->active != 0) && (state->delayTimer <= 0) && (state->needsOpenSfx != 0))
        {
            state->needsOpenSfx = 0;
            ((void (*)(void*, int))Sfx_PlayFromObject)(obj, SFXmn_sml_trex_snap1);
        }

        if (state->active != state->previousActive)
        {
            if (state->active != 0)
            {
                resource = Resource_Acquire(TRICKY_EGG_EFFECT_RESOURCE_ID, 1);
                resourceArgs[1] = state->sequenceIndex * 2 + 0x19d;
                resourceArgs[2] = state->sequenceIndex * 2 + 0x19e;
                (*(void (*)(void*, int, u8*, int, int, u32*))(*(int*)(*(int*)resource + 4)))(
                    obj, 1, effectBuf.args, 0x10004, -1, resourceArgs);
                Resource_Release(resource);

                i = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, DIMTRICKY_PARTFX_EGG_ACTIVATE, NULL, 0, -1, NULL);
                    i++;
                }
                while (i < 100);

                if ((state->gameBitId != -1) && (mainGetBit(state->gameBitId) == 0))
                {
                    mainSetBits(state->gameBitId, 1);
                }
                if ((gDimTrickyEggSequenceStage == 0) && (state->sequenceIndex == 0) &&
                    (mainGetBit(state->gameBitId) != 0))
                {
                    gDimTrickyEggSequenceStage = 1;
                }
                if ((gDimTrickyEggSequenceStage == 1) && (state->sequenceIndex == 1) &&
                    (mainGetBit(state->gameBitId) != 0))
                {
                    gDimTrickyEggSequenceStage = 2;
                }
                if ((gDimTrickyEggSequenceStage == 2) && (state->sequenceIndex == 2) &&
                    (mainGetBit(state->gameBitId) != 0))
                {
                    mainSetBits(GAMEBIT_TRICKY_EGG_SEQUENCE_DONE, 1);
                    gDimTrickyEggSequenceStage = 3;
                }
                state->needsOpenSfx = 1;
                state->delayTimer = 1;
            }
            else
            {
                ((void (*)(void*, int))Sfx_StopObjectChannel)(obj, 0x40);
                (*gModgfxInterface)->detachSource(obj);
                (*gExpgfxInterface)->freeSource((u32)obj);
                if ((state->gameBitId != -1) && (mainGetBit(state->gameBitId) != 0))
                {
                    mainSetBits(state->gameBitId, 0);
                }
                if ((gDimTrickyEggSequenceStage == 1) && (state->sequenceIndex == 0))
                {
                    gDimTrickyEggSequenceStage = 0;
                }
                if ((gDimTrickyEggSequenceStage == 2) && (state->sequenceIndex == 1))
                {
                    gDimTrickyEggSequenceStage = 0;
                }
                if ((gDimTrickyEggSequenceStage == 3) && (state->sequenceIndex == 2) &&
                    (mainGetBit(GAMEBIT_TRICKY_EGG_CUTSCENE_DONE) == 0))
                {
                    mainSetBits(GAMEBIT_TRICKY_EGG_SEQUENCE_DONE, 0);
                    gDimTrickyEggSequenceStage = 0;
                }
            }
        }
    }
}

void dll_19E_init(u8* obj, Dll19ESetup* setup)
{
    Dll19EState* state;
    void* resource;
    struct
    {
        u8 args[16];
        f32 scale;
    } stackArg;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(((s32)setup->objectType & 0x3f) << 10);
    if (setup->scaleTimer > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = setup->scaleTimer / gDimTrickyScaleTimerDivisor;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E51E8;
    }

    state->mode = setup->mode;
    state->active = 0;
    state->sequenceIndex = 0;
    state->gameBitId = setup->gameBitId;
    stackArg.scale = lbl_803E51E0;

    switch (state->mode)
    {
    case DIM_TRICKY_MODE_SPARKLE:
        state->active = 1;
        resource = Resource_Acquire(TRICKY_EGG_EFFECT_RESOURCE_ID, 1);
        if (setup->sequenceIndex == 0)
        {
            (*(void (**)(u8*, int, u8*, int, int, int))(*(int*)resource + 4))(
                obj, 0, stackArg.args, 0x10004, -1, 0);
        }
        break;
    case DIM_TRICKY_MODE_EGG_INTERACT:
        state->sequenceIndex = setup->sequenceIndex;
        state->needsOpenSfx = 0;
        state->settleTimer = state->sequenceIndex * 0x28 + 0x398;
        state->previousActive = 0;
        break;
    }
    state->delayTimer = 0;
}

void dll_19E_release(void)
{
}

void dll_19E_initialise(void)
{
}
