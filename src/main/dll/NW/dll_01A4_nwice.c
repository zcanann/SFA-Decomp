/* DLL 0x01A4 - NW ice objects [801CF78C-801CF7E8) */
#include "main/objlib.h"
#include "main/game_object.h"

#define NWICE_OBJGROUP 0x3c

typedef struct NwIcePlacement
{
    u8 pad0[0x1B - 0x0];
    u8 linkId; /* pairing key: matched against another nwice's 0x1B to find linkedObj */
    u8 pad1C[0x20 - 0x1C];
} NwIcePlacement;

extern void fn_80296D20(int obj, void* arg);

typedef struct NwIceState
{
    int* linkedObj;
} NwIceState;

int nw_ice_getExtraSize(void) { return 0x4; }

void nw_ice_free(int x) { ObjGroup_RemoveObject(x, NWICE_OBJGROUP); }

void nw_ice_render(void)
{
}

void nw_ice_update(int* obj)
{
    extern int Obj_GetPlayerObject(void); /* #57 */
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
        ObjGroup_FindNearestObjectForObject(0x3c, (u32)obj, &nearestDist);

        if (((GameObject*)state->linkedObj)->anim.alpha < 0xc0)
        {
            ObjHits_DisableObject((u32)obj);
            fn_80296D20(Obj_GetPlayerObject(), obj);
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
        objects = (int**)ObjGroup_GetObjects(0x3d, &count);
        setup = *(NwIcePlacement**)&((GameObject*)obj)->anim.placementData;
        for (i = 0, scan = objects; i < count; scan++, i++)
        {
            candidate = *scan;
            if ((obj != candidate) &&
                (setup->linkId ==
                    *(u8*)((char*)*(int**)((char*)candidate + 0x4c) + 0x1b)))
            {
                state->linkedObj = objects[i];
                break;
            }
        }
    }
}

void nw_ice_init(int x) { ObjGroup_AddObject(x, NWICE_OBJGROUP); }
