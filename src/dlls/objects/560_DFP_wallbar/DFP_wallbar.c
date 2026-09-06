/*
 * Ocean Force Point Temple "chuka" wall-bar object (DLL 0x230; "DFP_wallbar").
 * Its callbacks retain the recovered chuka_* names for the moving
 * wall/floor bar driven by the shared baddie state machine.
 */
#include "main/dll_000A_expgfx.h"
#include "main/dll/baddie/chuka.h"
#include "main/dll/DF/dll_0229_dfplevelcontrol.h"
#include "main/gamebits.h"
#include "main/obj_list.h"
#include "main/dll/DF/dll_0230_dfpwallbar.h"
#include "sys/objects.h"

/* romDefNo of the Ocean Force Point level controller this bar links to. */
#define DFPWALLBAR_SEQID_CONTROLLER 0x431

extern u8 gDFPWallbarSafeFloorTiles[9];

int chuka_SeqFn(void)
{
    return 0x0;
}
int chuka_getExtraSize(void)
{
    return sizeof(ChukaState);
}
int chuka_getObjectTypeId(void)
{
    return 0x0;
}

void chuka_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((int)obj);
}

void chuka_render(void)
{
}

void chuka_hitDetect(GameObject* obj)
{
    GameObject* levelController;
    ChukaState* state = obj->extra;
    levelController = state->levelController;
    if (levelController == NULL)
        return;
    if ((levelController->anim.flags & 0x40) == 0)
        return;
    state->levelController = 0;
}

void chuka_update(GameObject* obj)
{
    ChukaPlacement* data = (ChukaPlacement*)obj->anim.placementData;
    ChukaState* state = obj->extra;
    GameObject* levelController;
    GameObject** objList;
    GameObject* candidate;
    int i;
    int height;
    int firstIdx;
    int count;
    ObjAnimComponent* objAnim = &obj->anim;

    levelController = state->levelController;
    if (levelController != NULL)
    {
        if (levelController->anim.flags & 0x40)
        {
            state->levelController = 0;
            return;
        }
    }
    if ((void*)levelController == NULL)
    {
        objList = ObjList_GetObjects(&firstIdx, &count);
        for (i = firstIdx; i < count; i++)
        {
            candidate = (GameObject*)objList[i];
            if (candidate->anim.romDefNo == DFPWALLBAR_SEQID_CONTROLLER)
            {
                state->levelController = candidate;
                i = count;
            }
        }
        if (state->levelController == NULL)
        {
            return;
        }
    }
    levelController = state->levelController;
    DFP_LEVEL_CONTROL_INTERFACE(levelController)->copySafeFloorTiles(levelController, gDFPWallbarSafeFloorTiles);
    if (mainGetBit(GAMEBIT_OFP_PuzzlePadShowSolution) == 0)
    {
        state->safeTileIndex = 0;
    }
    else
    {
        state->safeTileIndex = gDFPWallbarSafeFloorTiles[state->rowIndex];
    }
    switch (state->safeTileIndex)
    {
    case 0:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        height = data->barHeight;
        if (height != 0)
        {
            obj->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        break;
    case 1:
        if (objAnim->bankIndex != 1)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        height = data->barHeight;
        if (height != 0)
        {
            obj->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if (obj->anim.rotZ != 0) {
            obj->anim.rotZ = 0;
        }
        break;
    case 2:
        if (objAnim->bankIndex != 2)
        {
            Obj_SetActiveModelIndex(obj, 2);
        }
        height = data->barHeight;
        if (height != 0)
        {
            obj->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if (obj->anim.rotZ != 0) {
            obj->anim.rotZ = 0;
        }
        break;
    case 3:
        if (objAnim->bankIndex != 2)
        {
            Obj_SetActiveModelIndex(obj, 2);
        }
        height = data->barHeight;
        if (height != 0)
        {
            obj->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if (obj->anim.rotZ != 0x3fff) {
            obj->anim.rotZ = 0x7fff;
        }
        break;
    case 4:
        if (objAnim->bankIndex != 1)
        {
            Obj_SetActiveModelIndex(obj, 1);
        }
        height = data->barHeight;
        if (height != 0)
        {
            obj->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if (obj->anim.rotZ != 0x3fff) {
            obj->anim.rotZ = 0x7fff;
        }
        break;
    default:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        height = data->barHeight;
        if (height != 0)
        {
            obj->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if (obj->anim.rotZ != 0) {
            obj->anim.rotZ = 0;
        }
        break;
    }
}

void chuka_init(GameObject* obj, ChukaPlacement* params)
{
    ChukaState* state = obj->extra;
    ChukaPlacement* placement = params;
    u8* safeFloorTiles;

    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = chuka_SeqFn;
    state->startY = obj->anim.localPosY;
    state->rowIndex = placement->rowIndex;

    if (placement->barHeight != 0)
    {
        obj->anim.rootMotionScale = 1.0f / ((f32)placement->barHeight / 1000.0f);
    }

    if (placement->rotZInit != 0)
    {
        obj->anim.rotZ = placement->rotZInit;
    }

    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN;
    state->levelController = 0;

    safeFloorTiles = gDFPWallbarSafeFloorTiles;
    {
        int i;
        for (i = 9; i != 0; i--)
        {
            *safeFloorTiles = 0;
            safeFloorTiles++;
        }
    }
}

void chuka_release(void)
{
}

void chuka_initialise(void)
{
}

u8 gDFPWallbarSafeFloorTiles[9] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0,
};

ObjectDescriptor10WithPadding gChukaObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)chuka_initialise,
        (ObjectDescriptorCallback)chuka_release,
        0,
        (ObjectDescriptorCallback)chuka_init,
        (ObjectDescriptorCallback)chuka_update,
        (ObjectDescriptorCallback)chuka_hitDetect,
        (ObjectDescriptorCallback)chuka_render,
        (ObjectDescriptorCallback)chuka_free,
        (ObjectDescriptorCallback)chuka_getObjectTypeId,
        chuka_getExtraSize,
    },
    0,
};
