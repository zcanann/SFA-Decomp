#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/game_timer_control_api.h"
#include "main/objhits.h"
#include "sys/objects.h"
#include "main/mapEvent.h"
#include "dlls/objects/562_DFP_RotateP.h"
#include "main/dll/dll_02B1_cmbsrc.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct CmbSrcColorIndexPair
{
    u32 a;
    u32 b;
} CmbSrcColorIndexPair;

#define DFP_ROTATEP_EFFECT_RING_COUNT       4
#define DFP_ROTATEP_EFFECT_HANDLES_PER_RING 2
#define DFP_ROTATEP_MODE_SEQUENCE           2
#define DFP_ROTATEP_RING_START_SFX          0x459
#define DFP_ROTATEP_TIMEOUT_RESET_SFX       0x1CE
#define DFP_ROTATEP_GAMEBIT_RING_ACTIVE     0xEDF
#define DFP_ROTATEP_RING_VISUAL_SETUP_SIZE  0x2C
#define DFP_ROTATEP_RING_VISUAL_OBJECT_ID   CMBSRC_SEQ_DEFAULT
#define DFP_ROTATEP_RING_HIT_SETUP_SIZE     4
#define DFP_ROTATEP_RING_HIT_OBJECT_ID      0x71C
#define DFP_ROTATEP_RING_SETUP_MODE         5
#define DFP_ROTATEP_EFFECT_RING_ROT_STEP    0x3FFF

#define DFP_ROTATEP_COMPLETE_RING_COUNT     4
#define DFP_ROTATEP_TIMER_ID                0x1D
#define DFP_ROTATEP_TIMER_SHORT_FRAMES      0x96
#define DFP_ROTATEP_TIMER_LONG_FRAMES       0xB4
#define DFP_ROTATEP_MODE_SINGLE             1
#define DFP_ROTATEP_GAMEBIT_SINGLE_COMPLETE 0x9F7
#define DFP_ROTATEP_SFX_COMPLETE            0x7E
#define DFP_ROTATEP_SFX_TIMEOUT_RESET       0x1CE
#define DFP_ROTATEP_SFX_RING_HIT            0x409
#define DFP_ROTATEP_HIT_TYPE_RING_TARGET    0x13

int gDFP_RotatePEffectHandles[8];

static const CmbSrcColorIndexPair sDFPRotatePColorIndices = {0x00040005, 0x0006000B};

#define DFP_ROTATEP_UPDATE_EFFECT_HANDLE_POS(handleExpr, obj, rot, angleStep)                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((void*)(handleExpr) != NULL)                                                                               \
        {                                                                                                              \
            *(f32*)((handleExpr) + 0xc) = 0.0f;                                                                        \
            *(f32*)((handleExpr) + 0x10) = 60.0f;                                                                      \
            *(f32*)((handleExpr) + 0x14) = 93.0f;                                                                      \
            (rot)[0] = (s16)(*(s16*)(obj) + (angleStep));                                                              \
            vecRotateZXY((rot), (f32*)((handleExpr) + 0xc));                                                           \
            *(f32*)((handleExpr) + 0xc) += *(f32*)((obj) + 0xc);                                                       \
            *(f32*)((handleExpr) + 0x10) += *(f32*)((obj) + 0x10);                                                     \
            *(f32*)((handleExpr) + 0x14) += *(f32*)((obj) + 0x14);                                                     \
        }                                                                                                              \
    } while (0)

void DFP_RotateP_updateEffectHandleRing(GameObject* obj)
{
    struct
    {
        s16 rotation[4];
        f32 baseVec[4];
    } buf;
    int* handles;
    DFPRotatePState* state = (DFPRotatePState*)obj->extra;
    s16 i;

    if (state->flags.bit10 != 0 && state->flags.bit20 == 0 && state->variantSfxTimer > 0x32)
    {
        Sfx_KeepAliveLoopedObjectSound(obj, DFP_ROTATEP_RING_START_SFX);
        if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == DFP_ROTATEP_MODE_SEQUENCE)
        {
            obj->anim.rotX += (int)((1.0f + state->ringCount) * (30.0f * timeDelta));
        }
        else
        {
            obj->anim.rotX += (int)(30.0f * timeDelta);
        }
    }

    if (state->variantSfxTimer != 0 && state->flags.bit10 != 0)
    {
        state->variantSfxTimer -= (s16)timeDelta;
        if (state->variantSfxTimer <= 0)
        {
            state->variantSfxTimer = 200;
        }
    }

    buf.baseVec[1] = 0.0f;
    buf.baseVec[2] = 0.0f;
    buf.baseVec[3] = 0.0f;
    buf.baseVec[0] = 1.0f;
    buf.rotation[1] = buf.rotation[2] = 0;
    handles = gDFP_RotatePEffectHandles;

    for (i = 0; i < DFP_ROTATEP_EFFECT_RING_COUNT; i++)
    {
        DFP_ROTATEP_UPDATE_EFFECT_HANDLE_POS(handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING], (int)obj,
                                             buf.rotation, i * DFP_ROTATEP_EFFECT_RING_ROT_STEP);
        DFP_ROTATEP_UPDATE_EFFECT_HANDLE_POS(handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1], (int)obj,
                                             buf.rotation, i * DFP_ROTATEP_EFFECT_RING_ROT_STEP);
    }
}

int DFP_RotateP_ensureEffectHandlePair(GameObject* obj, u8 ringIndex)
{
    u32 colorIndexWords[2];
    int* handles;
    int* pair;
    CmbSrcMapData* setup;
    int handleOffset;
    s16* colorIndices;

    *(CmbSrcColorIndexPair*)colorIndexWords = sDFPRotatePColorIndices;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }

    handleOffset = (ringIndex & 0xff) * 8;
    handles = gDFP_RotatePEffectHandles;
    if (*(void**)((int)handles + handleOffset) == NULL)
    {
        setup = (CmbSrcMapData*)Obj_AllocObjectSetup(DFP_ROTATEP_RING_VISUAL_SETUP_SIZE,
                                                     DFP_ROTATEP_RING_VISUAL_OBJECT_ID);
        setup->base.color[2] = 0xff;
        setup->base.color[3] = 0xff;
        setup->base.color[0] = 2;
        setup->base.color[1] = 1;
        setup->base.posX = obj->anim.localPosX;
        setup->base.posY = obj->anim.localPosY;
        setup->base.posZ = obj->anim.localPosZ;
        setup->gameBit = -1;
        setup->rotX = 0;
        setup->rotZ = 0;
        setup->rotY = 0;
        if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == DFP_ROTATEP_MODE_SEQUENCE)
        {
            colorIndices = (s16*)colorIndexWords;
            setup->colorIndex = colorIndices[ringIndex & 0xff];
        }
        else
        {
            setup->colorIndex = (u8) * (s16*)((char*)colorIndexWords + 6);
        }
        setup->effectMode = 0;
        setup->pulseSubMode = 0;
        setup->colorDistance = 0x64;
        setup->effectDistance = 0;
        setup->pulseDistance = 0;
        setup->radius = 0.5f;
        setup->flags = 0xd2;
        setup->behaviorFlags = 0;
        *(int*)((int)handles + handleOffset) = (int)objSetupObject(&setup->base, DFP_ROTATEP_RING_SETUP_MODE,
                                                                    obj->anim.mapEventSlot, -1, obj->anim.parent);
    }

    {
        u8* pairBase = (u8*)gDFP_RotatePEffectHandles + 4;
        pair = (int*)(pairBase + ((ringIndex & 0xff) * 8));
    }
    if (*(void**)pair == NULL)
    {
        setup = (CmbSrcMapData*)Obj_AllocObjectSetup(DFP_ROTATEP_RING_HIT_SETUP_SIZE, DFP_ROTATEP_RING_HIT_OBJECT_ID);
        setup->base.color[2] = 0xff;
        setup->base.color[3] = 0xff;
        setup->base.color[0] = 2;
        setup->base.color[1] = 1;
        setup->base.posX = obj->anim.localPosX;
        setup->base.posY = obj->anim.localPosY;
        setup->base.posZ = obj->anim.localPosZ;
        *pair = (int)objSetupObject(&setup->base, DFP_ROTATEP_RING_SETUP_MODE, obj->anim.mapEventSlot, -1,
                                    obj->anim.parent);
    }

    return 1;
}

int DFP_RotateP_activateEffectHandleRing(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    DFPRotatePState* state = (DFPRotatePState*)obj->extra;
    int i;

    state->flags.bit80 = 1;
    gameTimerStop();
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch ((int)animUpdate->eventIds[i])
        {
        case 1:
            state->flags.bit10 = 1;
            state->ringCount = 0;
            mainSetBits(state->activationEventId, 0);
            mainSetBits(DFP_ROTATEP_GAMEBIT_RING_ACTIVE, 1);
            for (i = 0; i < DFP_ROTATEP_EFFECT_RING_COUNT; i++)
            {
                DFP_RotateP_ensureEffectHandlePair(obj, i);
            }
            state->flags.bit40 = 1;
            break;
        }
    }

    DFP_RotateP_updateEffectHandleRing(obj);
    return 0;
}

int DFP_RotateP_getExtraSize(void)
{
    return 0xa;
}
int DFP_RotateP_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_RotateP_free(GameObject* obj, int flag)
{
    u32* handles;
    s16 i;

    if (flag == 0)
    {
        handles = (u32*)gDFP_RotatePEffectHandles;
        for (i = 0; i < DFP_ROTATEP_EFFECT_RING_COUNT; i++)
        {
            if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] != 0)
            {
                Obj_FreeObject((GameObject*)handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING]);
            }
            handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] = 0;
            if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1] != 0)
            {
                Obj_FreeObject((GameObject*)handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1]);
            }
            handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1] = 0;
            Sfx_PlayFromObject(obj, DFP_ROTATEP_TIMEOUT_RESET_SFX);
        }
    }
    gameTimerStop();
}

#undef DFP_ROTATEP_UPDATE_EFFECT_HANDLE_POS

void DFP_RotateP_render(void)
{
}

void DFP_RotateP_hitDetect(void)
{
}

void DFP_RotateP_update(GameObject* obj)
{
    u32* handles;
    s16 i;
    s16 hitType;
    u8 mode;
    DFPRotatePState* state;
    DFPRotatePStateFlags* flags;
    GameObject* hitObj;

    state = (DFPRotatePState*)obj->extra;
    flags = &state->flags;
    if ((flags->bit20 == 0) && (mainGetBit(state->eventId) == 0))
    {
        if (state->ringCount == DFP_ROTATEP_COMPLETE_RING_COUNT)
        {
            Sfx_PlayFromObject(0, DFP_ROTATEP_SFX_COMPLETE);
            flags->bit20 = 1;
            flags->bit10 = 0;
            flags->bit40 = 0;
            mainSetBits(state->eventId, 1);
            mainSetBits(DFP_ROTATEP_GAMEBIT_RING_ACTIVE, 0);
            mode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
            if (mode == DFP_ROTATEP_MODE_SINGLE)
            {
                mainSetBits(DFP_ROTATEP_GAMEBIT_SINGLE_COMPLETE, 1);
            }
            gameTimerStop();
        }
        else
        {
            if (flags->bit80 != 0)
            {
                flags->bit80 = 0;
                if (flags->bit10 != 0)
                {
                    mode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
                    if (mode == DFP_ROTATEP_MODE_SINGLE)
                    {
                        gameTimerInit(DFP_ROTATEP_TIMER_ID, DFP_ROTATEP_TIMER_SHORT_FRAMES);
                    }
                    else
                    {
                        gameTimerInit(DFP_ROTATEP_TIMER_ID, DFP_ROTATEP_TIMER_LONG_FRAMES);
                    }
                    timerSetToCountUp();
                }
            }
            if (isGameTimerDisabled() != 0)
            {
                handles = (u32*)gDFP_RotatePEffectHandles;
                for (i = 0; i < DFP_ROTATEP_EFFECT_RING_COUNT; i++)
                {
                    if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] != 0)
                    {
                        Obj_FreeObject((GameObject*)handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING]);
                    }
                    handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] = 0;
                    if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1] != 0)
                    {
                        Obj_FreeObject((GameObject*)handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1]);
                    }
                    handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1] = 0;
                    Sfx_PlayFromObject(obj, DFP_ROTATEP_SFX_TIMEOUT_RESET);
                }
                state->ringCount = 0;
                flags->bit40 = 0;
                flags->bit10 = 0;
                mainSetBits(DFP_ROTATEP_GAMEBIT_RING_ACTIVE, 0);
            }
            DFP_RotateP_updateEffectHandleRing(obj);
            handles = (u32*)gDFP_RotatePEffectHandles;
            for (i = 0; i < DFP_ROTATEP_EFFECT_RING_COUNT; i++)
            {
                if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] != 0)
                {
                    hitObj = NULL;
                    hitType = ObjHits_GetPriorityHit(
                        (GameObject*)(handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1]), &hitObj, 0x0, 0x0);
                    if (hitType == DFP_ROTATEP_HIT_TYPE_RING_TARGET)
                    {
                        mode = (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
                        if ((mode == DFP_ROTATEP_MODE_SINGLE) || (hitObj->userData1 == i))
                        {
                            if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] != 0)
                            {
                                Obj_FreeObject((GameObject*)handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING]);
                            }
                            handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING] = 0;
                            if (handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1] != 0)
                            {
                                Obj_FreeObject((GameObject*)handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1]);
                            }
                            handles[i * DFP_ROTATEP_EFFECT_HANDLES_PER_RING + 1] = 0;
                            Sfx_PlayFromObject(0, DFP_ROTATEP_SFX_RING_HIT);
                            state->ringCount++;
                        }
                    }
                }
            }
        }
    }
    return;
}

void DFP_RotateP_init(GameObject* obj, DFPRotatePPlacement* placement)
{
    DFPRotatePState* state;

    state = (DFPRotatePState*)obj->extra;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = (void*)DFP_RotateP_activateEffectHandleRing;
    state->config19 = placement->unknown19;
    state->eventId = placement->eventGameBit;
    state->config20 = placement->activationGameBit;
    state->unk4 = 1;
    gDFP_RotatePEffectHandles[0] = 0;
    gDFP_RotatePEffectHandles[1] = 0;
    gDFP_RotatePEffectHandles[2] = 0;
    gDFP_RotatePEffectHandles[3] = 0;
    gDFP_RotatePEffectHandles[4] = 0;
    gDFP_RotatePEffectHandles[5] = 0;
    gDFP_RotatePEffectHandles[6] = 0;
    gDFP_RotatePEffectHandles[7] = 0;
    gameTimerStop();
    if (mainGetBit(state->eventId) != 0)
    {
        state->flags.bit20 = 1;
    }
    obj->objectFlags = obj->objectFlags | (OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN);
}

void DFP_RotateP_release(void)
{
}

void DFP_RotateP_initialise(void)
{
}

ObjectDescriptor gDFP_RotatePObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFP_RotateP_initialise,
    (ObjectDescriptorCallback)DFP_RotateP_release,
    0,
    (ObjectDescriptorCallback)DFP_RotateP_init,
    (ObjectDescriptorCallback)DFP_RotateP_update,
    (ObjectDescriptorCallback)DFP_RotateP_hitDetect,
    (ObjectDescriptorCallback)DFP_RotateP_render,
    (ObjectDescriptorCallback)DFP_RotateP_free,
    (ObjectDescriptorCallback)DFP_RotateP_getObjectTypeId,
    DFP_RotateP_getExtraSize,
};
