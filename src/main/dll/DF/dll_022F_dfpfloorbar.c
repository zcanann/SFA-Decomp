/*
 * DragonRock Palace floor bar (DLL 0x22F; "DFP_floorbar") - a rising/
 * falling floor bar in the spell puzzle. It links to the puzzle
 * controller object (seqId 0x431) to read the per-mode required score
 * table, lowers itself while sequence game bits are set, and raises when
 * the player stands in the correct scoring zone (matched against
 * requiredScore); a wrong zone trips game bit 0x5e5 to reset.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/baddie/dll_022F_dfpfloorbar.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/obj_placement.h"
#include "main/mapEvent.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/gamebit_ids.h"

typedef struct DfpfloorbarPlacement
{
    u8 pad0[0xC - 0x0];
    f32 posY;
    u8 pad10[0x18 - 0x10];
    u8 rotXByte;  /* 0x18: <<8 seeds anim.rotX */
    u8 modeIndex; /* 0x19: selects the mode-table row */
    u8 pad1A[0x1C - 0x1A];
    s16 travelRange;       /* 0x1C: nonzero scales rootMotionScale */
    s16 triggerGameBit;    /* 0x1E */
    s16 completionGameBit; /* 0x20 */
} DfpfloorbarPlacement;

/* anim.seqId of the puzzle controller object this bar links to (docblock:
 * "the puzzle controller object (seqId 0x431)"). */
#define DFPFLOORBAR_CONTROLLER_SEQID 0x431

extern f32 lbl_803E6408;
extern f32 lbl_803E640C;
extern f32 lbl_803E6410;
extern f32 lbl_803E6414;

int dfpfloorbar_SeqFn(void)
{
    return 0;
}

int DFP_Floorbar_getExtraSize(void)
{
    return 0xc;
}

int DFP_Floorbar_getObjectTypeId(void)
{
    return 0;
}

void DFP_Floorbar_free(int* obj)
{
    DfpFloorbarState* state;

    state = (DfpFloorbarState*)*(int*)&((GameObject*)obj)->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    state->linkedObject = NULL;
    return;
}

void DFP_Floorbar_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 t = visible;
    if (t != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E6408);
    }
}

void DFP_Floorbar_hitDetect(int* obj)
{
    int* linkedObject;
    int** state;
    s32 hitFlag;
    state = (int**)*(int*)&((GameObject*)obj)->extra;
    linkedObject = state[2];
    if (linkedObject == NULL)
        return;
    hitFlag = *(s16*)((char*)linkedObject + 6) & 0x40;
    if (hitFlag == 0)
        return;
    state[2] = NULL;
}

u8 gDfpfloorbarModeTable[DFPFLOORBAR_MODE_TABLE_STORAGE] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

void DFP_Floorbar_update(GameObject* obj)
{
    int placement = *(int*)&(obj)->anim.placementData;
    DfpFloorbarState* state = (obj)->extra;
    s16 score = -1;
    int mode;
    u8 active;
    u32 sequenceValue;
    GameObject* playerObj;
    f32 yDelta;
    f32 xMid;
    f32 zDelta;

    mode = (obj)->anim.mapEventSlot;
    mode = (*gMapEventInterface)->getMapAct(mode);

    switch ((u8)mode)
    {
    case 1:
        if (state->modeIndex > 5)
            return;
        if (mainGetBit(0xe57) != 0)
        {
            (obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->posY - lbl_803E640C;
            return;
        }
        break;
    case 2:
        if (mainGetBit(0xe58) != 0)
        {
            (obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->posY - lbl_803E640C;
            return;
        }
        break;
    }

    sequenceValue = (u8)mainGetBit(GAMEBIT_DRBOT_SpellPuzzleActive);
    if (mainGetBit(0x5e5) != 0 || sequenceValue != state->lastSequenceValue)
    {
        state->active = 0;
    }
    state->lastSequenceValue = sequenceValue;

    if (state->linkedObject == NULL)
    {
        int* items;
        int idx_init;
        int count;
        int idx;
        items = ObjList_GetObjects(&idx_init, &count);
        idx = idx_init;
        for (; idx < count; idx++)
        {
            if (((GameObject*)items[idx])->anim.seqId == DFPFLOORBAR_CONTROLLER_SEQID)
            {
                state->linkedObject = (int*)items[idx];
                idx = count;
            }
        }
        if (state->linkedObject == NULL)
            return;
    }

    {
        int objPtr = (int)state->linkedObject;
        (*(VtableFn*)(**(int**)(objPtr + 0x68) + 0x20))(objPtr, gDfpfloorbarModeTable);
    }

    state->requiredScore = gDfpfloorbarModeTable[state->modeIndex];

    active = state->active;
    if (active != 0 && (obj)->anim.localPosY > ((DfpfloorbarPlacement*)placement)->posY - lbl_803E640C)
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_en_treedrum16_1c8);
        (obj)->anim.localPosY = (obj)->anim.localPosY - timeDelta / lbl_803E6410;
        if ((obj)->anim.localPosY <= ((DfpfloorbarPlacement*)placement)->posY - lbl_803E640C)
        {
            (obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->posY - lbl_803E640C;
        }
        return;
    }

    if (state->requiredScore == 0)
        return;
    if (active == 0)
    {
        (obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->posY;
    }
    if (state->active != 0)
        return;

    playerObj = Obj_GetPlayerObject();
    if (playerObj == NULL)
        return;

    yDelta = obj->anim.localPosY - playerObj->anim.localPosY;
    if (yDelta < 0.0f)
        yDelta = yDelta * lbl_803E6414;
    if (yDelta < 100.0f)
    {
        xMid = playerObj->anim.localPosX - (obj->anim.localPosX - 100.0f);
        zDelta = obj->anim.localPosZ - playerObj->anim.localPosZ;
        if (zDelta < 0.0f)
            zDelta = zDelta * lbl_803E6414;
        if (zDelta < 18.0f)
        {
            if (xMid >= 150.0f)
            {
                score = 4;
            }
            else if (xMid >= 100.0f)
            {
                score = 3;
            }
            else if (xMid >= 50.0f)
            {
                score = 2;
            }
            else if (xMid >= 0.0f)
            {
                score = 1;
            }

            if (score == (s16)state->requiredScore)
            {
                state->active = 1;
                return;
            }

            mainSetBits(0x5e5, 1);
        }
    }
}

void DFP_Floorbar_init(GameObject* obj, int params)
{
    DfpFloorbarState* state = obj->extra;

    obj->anim.rotX = (s16)((s8)((DfpfloorbarPlacement*)params)->rotXByte << 8);
    obj->animEventCallback = dfpfloorbar_SeqFn;
    state->modeIndex = ((DfpfloorbarPlacement*)params)->modeIndex;
    state->triggerGameBit = ((DfpfloorbarPlacement*)params)->triggerGameBit;
    state->completionGameBit = ((DfpfloorbarPlacement*)params)->completionGameBit;
    state->linkedObject = NULL;

    if (((DfpfloorbarPlacement*)params)->travelRange != 0)
    {
        obj->anim.rootMotionScale = lbl_803E6408 / ((f32)(s32)((DfpfloorbarPlacement*)params)->travelRange / 1000.0f);
    }

    if (mainGetBit((int)state->completionGameBit) != 0)
    {
        state->active = 1;
        obj->anim.localPosY = ((DfpfloorbarPlacement*)params)->posY - lbl_803E640C;
    }
}

void DFP_Floorbar_release(void)
{
}

void DFP_Floorbar_initialise(void)
{
    u8* modeRow = gDfpfloorbarModeTable;
    int i;

    for (i = 0; i < DFPFLOORBAR_MODE_ROW_COUNT; i++, modeRow += DFPFLOORBAR_MODE_ROW_SIZE)
    {
        modeRow[0] = 0;
        modeRow[1] = 0;
        modeRow[2] = 0;
    }
}

ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)DFP_Floorbar_initialise,
        (ObjectDescriptorCallback)DFP_Floorbar_release,
        0,
        (ObjectDescriptorCallback)DFP_Floorbar_init,
        (ObjectDescriptorCallback)DFP_Floorbar_update,
        (ObjectDescriptorCallback)DFP_Floorbar_hitDetect,
        (ObjectDescriptorCallback)DFP_Floorbar_render,
        (ObjectDescriptorCallback)DFP_Floorbar_free,
        (ObjectDescriptorCallback)DFP_Floorbar_getObjectTypeId,
        DFP_Floorbar_getExtraSize,
    },
    0,
};

extern void sfxplayer_getExtraSize();
extern void sfxplayer_getObjectTypeId();
extern void sfxplayer_free();
extern void sfxplayer_render();
extern void sfxplayer_hitDetect();
extern void sfxplayer_update();
extern void sfxplayer_init();
extern void sfxplayer_release();
extern void sfxplayer_initialise();
extern void TrickyCurve_getExtraSize();
extern void TrickyCurve_getObjectTypeId();
extern void TrickyCurve_free();
extern void TrickyCurve_render();
extern void TrickyCurve_hitDetect();
extern void TrickyCurve_update();
extern void TrickyCurve_init();
extern void TrickyCurve_release();
extern void TrickyCurve_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gTrickyCurveObjDescriptor[14] = {(void*)0x00000000,           (void*)0x00000000,       (void*)0x00000000,
                                       (void*)0x00090000,           TrickyCurve_initialise,  TrickyCurve_release,
                                       (void*)0x00000000,           TrickyCurve_init,        TrickyCurve_update,
                                       TrickyCurve_hitDetect,       TrickyCurve_render,      TrickyCurve_free,
                                       TrickyCurve_getObjectTypeId, TrickyCurve_getExtraSize};
void* gSfxplayerObjDescriptor[14] = {(void*)0x00000000,         (void*)0x00000000,     (void*)0x00000000,
                                     (void*)0x00090000,         sfxplayer_initialise,  sfxplayer_release,
                                     (void*)0x00000000,         sfxplayer_init,        sfxplayer_update,
                                     sfxplayer_hitDetect,       sfxplayer_render,      sfxplayer_free,
                                     sfxplayer_getObjectTypeId, sfxplayer_getExtraSize};
