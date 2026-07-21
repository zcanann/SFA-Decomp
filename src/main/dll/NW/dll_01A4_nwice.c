/* DLL 0x01A4 - paired ice objects in Northern Wastes. */
#include "main/obj_group.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/NW/dll_01A4_nwice.h"
#include "main/dll/player_api.h"

#define NWICE_OBJGROUP      0x3c
#define NWICE_LINK_OBJGROUP 0x3d /* scanned to find the paired ice object by linkId */

int NW_ice_getExtraSize(void)
{
    return sizeof(NwIceState);
}

void NW_ice_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, NWICE_OBJGROUP);
}

void NW_ice_render(void)
{
}

void NW_ice_update(GameObject* obj)
{
    GameObject** scan;
    int i;
    NwIcePlacement* placement;
    NwIceState* state;
    GameObject** objects;
    GameObject* candidate;
    int count;
    f32 nearestDist;

    nearestDist = 3.4028235e38f;
    state = obj->extra;
    if (state->pairedIce != NULL)
    {
        obj->anim.localPosX = state->pairedIce->anim.localPosX;
        obj->anim.localPosY = state->pairedIce->anim.localPosY;
        obj->anim.localPosZ = state->pairedIce->anim.localPosZ;
        obj->anim.rotX = state->pairedIce->anim.rotX;
        ObjGroup_FindNearestObjectForObject(NWICE_OBJGROUP, obj, &nearestDist);

        if (state->pairedIce->anim.alpha < 0xc0)
        {
            ObjHits_DisableObject(obj);
            fn_80296D20(Obj_GetPlayerObject(), obj);
        }
        else
        {
            ObjHits_EnableObject(obj);
        }

        if ((state->pairedIce->anim.alpha < 0xc0) || (nearestDist < 120.0f))
        {
            obj->objectFlags = (u16)(obj->objectFlags | 0x100);
        }
        else
        {
            obj->objectFlags = (u16)(obj->objectFlags & ~0x100);
        }
    }
    else
    {
        objects = (GameObject**)ObjGroup_GetObjects(NWICE_LINK_OBJGROUP, &count);
        placement = (NwIcePlacement*)obj->anim.placementData;
        for (i = 0, scan = objects; i < count; scan++, i++)
        {
            candidate = *scan;
            if (obj != candidate &&
                placement->pairId == ((NwIcePlacement*)candidate->anim.placementData)->pairId)
            {
                state->pairedIce = objects[i];
                break;
            }
        }
    }
}

void NW_ice_init(GameObject* obj)
{
    ObjGroup_AddObject((int)obj, NWICE_OBJGROUP);
}
