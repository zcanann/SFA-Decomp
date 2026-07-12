/* DLL 0x01A4 - NW ice objects [801CF78C-801CF7E8) */
#include "main/objlib.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/NW/dll_01A4_nwice.h"

#define NWICE_OBJGROUP      0x3c
#define NWICE_LINK_OBJGROUP 0x3d /* scanned to find the paired ice object by linkId */

extern void fn_80296D20(int obj, void* arg);

int NW_ice_getExtraSize(void)
{
    return 0x4;
}

void NW_ice_free(int obj)
{
    ObjGroup_RemoveObject(obj, NWICE_OBJGROUP);
}

void NW_ice_render(void)
{
}

void NW_ice_update(int* obj)
{
    int** scan;
    int i;
    NwIcePlacement* setup;
    NwIceState* state;
    int** objects;
    int* candidate;
    int count;
    f32 nearestDist;

    nearestDist = 3.4028235e38f;
    state = ((GameObject*)obj)->extra;
    if (state->linkedObj != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)state->linkedObj)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)state->linkedObj)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)state->linkedObj)->anim.localPosZ;
        ((GameObject*)obj)->anim.rotX = ((GameObject*)state->linkedObj)->anim.rotX;
        ObjGroup_FindNearestObjectForObject(NWICE_OBJGROUP, (u32)obj, &nearestDist);

        if (((GameObject*)state->linkedObj)->anim.alpha < 0xc0)
        {
            ObjHits_DisableObject((u32)obj);
            fn_80296D20((int)Obj_GetPlayerObject(), obj);
        }
        else
        {
            ObjHits_EnableObject((u32)obj);
        }

        if ((((GameObject*)state->linkedObj)->anim.alpha < 0xc0) || (nearestDist < 120.0f))
        {
            ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x100);
        }
        else
        {
            ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags & ~0x100);
        }
    }
    else
    {
        objects = (int**)ObjGroup_GetObjects(NWICE_LINK_OBJGROUP, &count);
        setup = *(NwIcePlacement**)&((GameObject*)obj)->anim.placementData;
        for (i = 0, scan = objects; i < count; scan++, i++)
        {
            candidate = *scan;
            if ((obj != candidate) && (setup->linkId == *(u8*)((char*)*(int**)((char*)candidate + 0x4c) + 0x1b)))
            {
                state->linkedObj = objects[i];
                break;
            }
        }
    }
}

void NW_ice_init(int obj)
{
    ObjGroup_AddObject(obj, NWICE_OBJGROUP);
}
