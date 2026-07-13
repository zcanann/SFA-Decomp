/*
 * DragonRock Palace "chuka" wall-bar object (DLL 0x230; "DFP_wallbar").
 * The DLL's real object is the chuka_* family - a moving wall/floor bar
 * driven by the shared baddie state machine.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/baddie/chuka.h"
#include "main/gamebits.h"
#include "main/obj_list.h"
#include "main/gamebit_ids.h"
#include "main/dll/DF/dll_0230_dfpwallbar.h"

#pragma dont_inline on

#define DFPWALLBAR_OBJFLAG_HIDDEN 0x4000

/* seqId of the DragonRock spell-puzzle controller object this bar links
   to (stored as ChukaState.linkedObject; same controller as the floor bar). */
#define DFPWALLBAR_SEQID_CONTROLLER 0x431

extern u8 gChukaModeTable[9];

int chuka_SeqFn(void)
{
    return 0x0;
}
int chuka_getExtraSize(void)
{
    return 0xc;
}
int chuka_getObjectTypeId(void)
{
    return 0x0;
}

void chuka_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void chuka_render(void)
{
}

void chuka_hitDetect(GameObject* obj)
{
    GameObject* light;
    ChukaState* state = obj->extra;
    light = (GameObject*)state->linkedObject;
    if (light == NULL)
        return;
    if ((light->anim.flags & 0x40) == 0)
        return;
    state->linkedObject = 0;
}

void chuka_update(GameObject* obj)
{
    ChukaPlacement* data = (ChukaPlacement*)obj->anim.placementData;
    ChukaState* state = obj->extra;
    int linkedObj;
    int* objList;
    int candidate;
    int i;
    int height;
    int firstIdx;
    int count;
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;

    linkedObj = state->linkedObject;
    if ((u32)linkedObj != 0)
    {
        if (((GameObject*)linkedObj)->anim.flags & 0x40)
        {
            state->linkedObject = 0;
            return;
        }
    }
    if ((void*)linkedObj == NULL)
    {
        objList = ObjList_GetObjects(&firstIdx, &count);
        for (i = firstIdx; i < count; i++)
        {
            candidate = objList[i];
            if (((GameObject*)candidate)->anim.seqId == DFPWALLBAR_SEQID_CONTROLLER)
            {
                state->linkedObject = candidate;
                i = count;
            }
        }
        if ((void*)state->linkedObject == NULL)
        {
            return;
        }
    }
    linkedObj = state->linkedObject;
    (*(void (**)(int, u8*))(*((GameObject*)linkedObj)->anim.dll + 8))(linkedObj, gChukaModeTable);
    if (mainGetBit(GAMEBIT_DRBOT_SpellPuzzleActive) == 0)
    {
        state->mode = 0;
    }
    else
    {
        state->mode = gChukaModeTable[state->modeIndex];
    }
    switch (state->mode)
    {
    case 0:
        if (objAnim->bankIndex != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
        }
        height = data->barHeight;
        if (height != 0)
        {
            (obj)->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
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
            (obj)->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if ((obj)->anim.rotZ != 0)
        {
            (obj)->anim.rotZ = 0;
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
            (obj)->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if ((obj)->anim.rotZ != 0)
        {
            (obj)->anim.rotZ = 0;
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
            (obj)->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if ((obj)->anim.rotZ != 0x3fff)
        {
            (obj)->anim.rotZ = 0x7fff;
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
            (obj)->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if ((obj)->anim.rotZ != 0x3fff)
        {
            (obj)->anim.rotZ = 0x7fff;
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
            (obj)->anim.rootMotionScale = 1.0f / ((f32)height / 1000.0f);
        }
        if ((obj)->anim.rotZ != 0)
        {
            (obj)->anim.rotZ = 0;
        }
        break;
    }
}

void chuka_init(GameObject* obj, ChukaPlacement* params)
{
    ChukaState* state = obj->extra;
    ChukaPlacement* placement = params;
    u8* modeTable;

    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = chuka_SeqFn;
    state->startY = obj->anim.localPosY;
    state->modeIndex = placement->modeIndex;

    if (placement->barHeight != 0)
    {
        obj->anim.rootMotionScale = 1.0f / ((f32)placement->barHeight / 1000.0f);
    }

    if (placement->rotZInit != 0)
    {
        obj->anim.rotZ = placement->rotZInit;
    }

    obj->objectFlags |= DFPWALLBAR_OBJFLAG_HIDDEN;
    state->linkedObject = 0;

    modeTable = gChukaModeTable;
    {
        int i;
        for (i = 9; i != 0; i--)
        {
            *modeTable = 0;
            modeTable++;
        }
    }
}

void chuka_release(void)
{
}

void chuka_initialise(void)
{
}

u8 gChukaModeTable[9] = {
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
