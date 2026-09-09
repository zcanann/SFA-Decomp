/*
 * DFP_floorbar (DLL slot 559 / 0x22F): a
 * rising/falling row of the electric-floor puzzle. It links to the level
 * controller object (romDefNo 0x431) to read the safe tile for each row.
 */
#include "dlls/objects/559_DFP_floorba.h"

#include "main/audio/sfx_keep_alive_api.h"
#include "main/dll_000A_expgfx.h"
#include "dlls/objects/553_DFP_LevelCo.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/mapEvent.h"
#include "main/obj_list.h"
#include "sys/objects.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"

#define DFPFLOORBAR_RESET_GROUP_COUNT 3
#define DFPFLOORBAR_RESET_GROUP_SIZE  3

int dfpfloorbar_SeqFn(void)
{
    return 0;
}

int DFP_Floorbar_getExtraSize(void)
{
    return sizeof(DfpFloorbarState);
}

int DFP_Floorbar_getObjectTypeId(void)
{
    return 0;
}

void DFP_Floorbar_free(GameObject* obj)
{
    DfpFloorbarState* state;

    state = (DfpFloorbarState*)obj->extra;
    (*gExpgfxInterface)->freeSource2((u32)obj);
    state->levelController = NULL;
    return;
}

void DFP_Floorbar_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 t = visible;
    if (t != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void DFP_Floorbar_hitDetect(GameObject* obj)
{
    GameObject* levelController;
    DfpFloorbarState* state;
    s32 hitFlag;
    state = obj->extra;
    levelController = state->levelController;
    if (levelController == NULL)
        return;
    hitFlag = levelController->anim.flags & 0x40;
    if (hitFlag == 0)
        return;
    state->levelController = NULL;
}

u8 gDFPFloorbarSafeFloorTiles[9] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,
};

void DFP_Floorbar_update(GameObject* obj)
{
    DfpFloorbarPlacementPrefix* placement = (DfpFloorbarPlacementPrefix*)obj->anim.placementData;
    DfpFloorbarState* state = obj->extra;
    s16 tileSteppedOn = -1;
    int mode;
    u8 lowered;
    u32 showSolutionState;
    GameObject* playerObj;
    f32 yDelta;
    f32 xMid;
    f32 zDelta;

    mode = obj->anim.mapEventSlot;
    mode = (*gMapEventInterface)->getMapAct(mode);

    switch ((u8)mode)
    {
    case 1:
        if (state->rowIndex > 5)
            return;
        if (mainGetBit(GAMEBIT_OFP_ElectricFloorPuzzleAct1Complete) != 0)
        {
            obj->anim.localPosY = placement->base.posY - 3.2f;
            return;
        }
        break;
    case 2:
        if (mainGetBit(GAMEBIT_OFP_ElectricFloorPuzzleAct2Complete) != 0)
        {
            obj->anim.localPosY = placement->base.posY - 3.2f;
            return;
        }
        break;
    }

    showSolutionState = (u8)mainGetBit(GAMEBIT_OFP_PuzzlePadShowSolution);
    if (mainGetBit(GAMEBIT_OFP_ZappedByFloorTiles) != 0 ||
        showSolutionState != state->previousShowSolutionState)
    {
        state->lowered = 0;
    }
    state->previousShowSolutionState = showSolutionState;

    if (state->levelController == NULL)
    {
        GameObject** items;
        int idx_init;
        int count;
        int idx;
        items = ObjList_GetObjects(&idx_init, &count);
        idx = idx_init;
        for (; idx < count; idx++)
        {
            if (((GameObject*)items[idx])->anim.romDefNo == DFP_LEVEL_CONTROL_OBJECT_ID)
            {
                state->levelController = items[idx];
                idx = count;
            }
        }
        if (state->levelController == NULL)
            return;
    }

    {
        GameObject* objPtr = state->levelController;
        DFP_LEVEL_CONTROL_INTERFACE(objPtr)->copySafeFloorTiles(objPtr, gDFPFloorbarSafeFloorTiles);
    }

    state->safeTileIndex = gDFPFloorbarSafeFloorTiles[state->rowIndex];

    lowered = state->lowered;
    if (lowered != 0 && obj->anim.localPosY > placement->base.posY - 3.2f) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_en_treedrum16_1c8);
        obj->anim.localPosY = obj->anim.localPosY - timeDelta / 12.0f;
        if (obj->anim.localPosY <= placement->base.posY - 3.2f) {
            obj->anim.localPosY = placement->base.posY - 3.2f;
        }
        return;
    }

    if (state->safeTileIndex == 0)
        return;
    if (lowered == 0)
    {
        obj->anim.localPosY = placement->base.posY;
    }
    if (state->lowered != 0)
        return;

    playerObj = Obj_GetPlayerObject();
    if (playerObj == NULL)
        return;

    yDelta = obj->anim.localPosY - playerObj->anim.localPosY;
    if (yDelta < 0.0f)
        yDelta *= -1.0f;
    if (yDelta < 100.0f)
    {
        xMid = playerObj->anim.localPosX - (obj->anim.localPosX - 100.0f);
        zDelta = obj->anim.localPosZ - playerObj->anim.localPosZ;
        if (zDelta < 0.0f)
            zDelta *= -1.0f;
        if (zDelta < 18.0f)
        {
            if (xMid >= 150.0f)
            {
                tileSteppedOn = 4;
            }
            else if (xMid >= 100.0f)
            {
                tileSteppedOn = 3;
            }
            else if (xMid >= 50.0f)
            {
                tileSteppedOn = 2;
            }
            else if (xMid >= 0.0f)
            {
                tileSteppedOn = 1;
            }

            if (tileSteppedOn == (s16)state->safeTileIndex)
            {
                state->lowered = 1;
                return;
            }

            mainSetBits(GAMEBIT_OFP_ZappedByFloorTiles, 1);
        }
    }
}

void DFP_Floorbar_init(GameObject* obj, DfpFloorbarPlacementPrefix* params)
{
    DfpFloorbarState* state = obj->extra;
    DfpFloorbarPlacementPrefix* placement = params;

    obj->anim.rotX = (s16)(placement->rotationHighByte << 8);
    obj->animEventCallback = dfpfloorbar_SeqFn;
    state->rowIndex = placement->rowIndex;
    state->placementGameBit1E = placement->placementGameBit1E;
    state->initialLoweredGameBit = placement->initialLoweredGameBit;
    state->levelController = NULL;

    if (placement->motionScaleDivisor != 0)
    {
        obj->anim.rootMotionScale = 1.0f / ((f32)(s32)placement->motionScaleDivisor / 1000.0f);
    }

    if (mainGetBit((int)state->initialLoweredGameBit) != 0)
    {
        state->lowered = 1;
        obj->anim.localPosY = placement->base.posY - 3.2f;
    }
}

void DFP_Floorbar_release(void)
{
}

void DFP_Floorbar_initialise(void)
{
    u8* safeFloorRows = gDFPFloorbarSafeFloorTiles;
    int i;

    for (i = 0; i < DFPFLOORBAR_RESET_GROUP_COUNT; i++, safeFloorRows += DFPFLOORBAR_RESET_GROUP_SIZE)
    {
        safeFloorRows[0] = 0;
        safeFloorRows[1] = 0;
        safeFloorRows[2] = 0;
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
