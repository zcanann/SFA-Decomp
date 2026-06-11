#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objlib.h"
#include "main/dll/baddie/chuka.h"
#include "main/dll/baddie/chukachuck.h"

typedef struct DfpfloorbarPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
} DfpfloorbarPlacement;


extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern u8* Obj_GetPlayerObject(void);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);

u8 gDfpfloorbarModeTable[DFPFLOORBAR_MODE_TABLE_STORAGE] = {
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
};
extern MapEventInterface** gMapEventInterface;
extern f32 timeDelta;
extern f32 lbl_803E6408;
extern f32 lbl_803E640C;
extern f32 lbl_803E6410;
extern f32 lbl_803E6414;
extern f32 lbl_803E6418;
extern f32 lbl_803E641C;
extern f32 lbl_803E6420;
extern f32 lbl_803E6424;
extern f32 lbl_803E6428;
extern f32 lbl_803E642C;

/*
 * --INFO--
 *
 * Function: dfpfloorbar_update
 * EN v1.0 Address: 0x8020652C
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x802065F0
 * EN v1.1 Size: 964b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpfloorbar_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    DfpFloorbarState* state = ((GameObject*)obj)->extra;
    s16 score = -1;
    int mode;
    u8 active;
    u32 r27;
    u8* playerObj;
    f32 yDelta;
    f32 xMid;
    f32 zDelta;

    mode = ((GameObject*)obj)->anim.mapEventSlot;
    mode = (*gMapEventInterface)->getMode(mode);

    switch ((u8)mode)
    {
    case 1:
        if (state->modeIndex > 5) return;
        if (GameBit_Get(0xe57) != 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->unkC - lbl_803E640C;
            return;
        }
        break;
    case 2:
        if (GameBit_Get(0xe58) != 0)
        {
            ((GameObject*)obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->unkC - lbl_803E640C;
            return;
        }
        break;
    }

    r27 = (u8)GameBit_Get(0x5e4);
    if (GameBit_Get(0x5e5) != 0 || r27 != state->lastSequenceValue)
    {
        state->active = 0;
    }
    state->lastSequenceValue = (u8)r27;

    if (state->linkedObject == NULL)
    {
        int* items;
        int idx_init;
        int count;
        int idx;
        items = (int*)ObjList_GetObjects(&idx_init, &count);
        idx = idx_init;
        for (; idx < count; idx++)
        {
            int o = items[idx];
            if (*(s16*)(o + 0x46) == 0x431)
            {
                state->linkedObject = (int*)o;
                idx = count;
            }
        }
        if (state->linkedObject == NULL) return;
    }

    {
        int objPtr = (int)state->linkedObject;
        (*(code*)(**(int**)(objPtr + 0x68) + 0x20))(objPtr, gDfpfloorbarModeTable);
    }

    state->requiredScore = gDfpfloorbarModeTable[state->modeIndex];

    active = state->active;
    if (active != 0)
    {
        if (((GameObject*)obj)->anim.localPosY > ((DfpfloorbarPlacement*)placement)->unkC - lbl_803E640C)
        {
            Sfx_KeepAliveLoopedObjectSound(obj, SFXfoot_water_walk_2);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - timeDelta / lbl_803E6410;
            if (((GameObject*)obj)->anim.localPosY <= ((DfpfloorbarPlacement*)placement)->unkC - lbl_803E640C)
            {
                ((GameObject*)obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->unkC - lbl_803E640C;
            }
        }
        return;
    }

    if (state->requiredScore == 0) return;
    if (active == 0)
    {
        ((GameObject*)obj)->anim.localPosY = ((DfpfloorbarPlacement*)placement)->unkC;
    }
    if (state->active != 0) return;

    playerObj = Obj_GetPlayerObject();
    if (playerObj == NULL) return;

    yDelta = ((GameObject*)obj)->anim.localPosY - *(f32*)(playerObj + 0x10);
    if (yDelta < 0.0f) yDelta = yDelta * lbl_803E6414;
    if (yDelta < 100.0f)
    {
        xMid = *(f32*)(playerObj + 0xc) - (((GameObject*)obj)->anim.localPosX - 100.0f);
        zDelta = ((GameObject*)obj)->anim.localPosZ - *(f32*)(playerObj + 0x14);
        if (zDelta < 0.0f) zDelta = zDelta * lbl_803E6414;
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

            if ((s16)score == (s16)state->requiredScore)
            {
                state->active = 1;
                return;
            }

            GameBit_Set(0x5e5, 1);
        }
    }
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_release
 * EN v1.0 Address: 0x80206928
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfpfloorbar_release(void)
{
}

/*
 * --INFO--
 *
 * Function: dfpfloorbar_init
 * EN v1.0 Address: 0x80206844
 * EN v1.0 Size: 228b
 */
void dfpfloorbar_init(int obj, int params)
{
    DfpFloorbarState* state = ((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (u8*)(params + 0x18) << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dfpfloorbar_SeqFn;
    state->modeIndex = *(u8*)(params + 0x19);
    state->triggerGameBit = *(s16*)(params + 0x1e);
    state->completionGameBit = *(s16*)(params + 0x20);
    state->linkedObject = NULL;

    if (*(s16*)(params + 0x1c) != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E6408 / ((f32)(s32) * (s16*)(params + 0x1c) / lbl_803E642C);
    }

    if (GameBit_Get((int)state->completionGameBit) != 0)
    {
        state->active = 1;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)params)->posY - lbl_803E640C;
    }
}

/* EN v1.0 0x8020692C  size: 60b */
void dfpfloorbar_initialise(void)
{
    u8* modeRow = gDfpfloorbarModeTable;

    modeRow[0] = 0;
    modeRow[1] = 0;
    modeRow[2] = 0;
    modeRow += DFPFLOORBAR_MODE_ROW_SIZE;
    modeRow[0] = 0;
    modeRow[1] = 0;
    modeRow[2] = 0;
    modeRow += DFPFLOORBAR_MODE_ROW_SIZE;
    modeRow[0] = 0;
    modeRow[1] = 0;
    modeRow[2] = 0;
}

ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)dfpfloorbar_initialise,
        (ObjectDescriptorCallback)dfpfloorbar_release,
        0,
        (ObjectDescriptorCallback)dfpfloorbar_init,
        (ObjectDescriptorCallback)dfpfloorbar_update,
        (ObjectDescriptorCallback)dfpfloorbar_hitDetect,
        (ObjectDescriptorCallback)dfpfloorbar_render,
        (ObjectDescriptorCallback)dfpfloorbar_free,
        (ObjectDescriptorCallback)dfpfloorbar_getObjectTypeId,
        dfpfloorbar_getExtraSize,
    },
    0,
};
