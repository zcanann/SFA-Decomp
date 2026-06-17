/*
 * nwice (DLL 0x1A4) - the static ice blocks of SnowHorn Wastes (map
 * 'nwastes', 0x0A).
 *
 * Each nwice instance pairs itself, by a placement tag byte, with one of
 * the animated nwanimice blocks (DLL 0x1A3, object group NW_ANIMICE) and
 * then mirrors that block's position and rotation every frame. When the
 * followed block fades out (alpha < ICE_FADE_ALPHA) the ice stops
 * colliding and notifies the player; it is also culled when it fades or
 * when another nwice block is too close.
 */
#include "main/objlib.h"

#include "main/game_object.h"
#include "main/dll/NW/nw_shared.h"

/* followed block alpha below which the ice decouples / stops colliding */
#define ICE_FADE_ALPHA 0xc0

typedef struct NwIcePlacement
{
    u8 pad0[0x1B];
    u8 pairId;             /* 0x1B: tag matched against the animice placement */
    u8 pad1C[0x20 - 0x1C];
} NwIcePlacement;

typedef struct NwIceState
{
    int* linkedObj;        /* 0x00: the nwanimice block this ice follows */
} NwIceState;

extern void fn_80296D20(int playerObj, int* obj);

extern f32 lbl_803E5270;   /* nearest-search seed distance */
extern f32 lbl_803E5274;   /* cull distance to the nearest other ice block */

void nw_ice_render(void)
{
}

int nw_ice_getExtraSize(void) { return sizeof(NwIceState); }

void nw_ice_free(int obj) { ObjGroup_RemoveObject(obj, NW_ICE_GROUP_ID); }

void nw_ice_update(int* obj)
{
    extern int Obj_GetPlayerObject(void);
    NwIceState* state;
    int* setup;
    int i;
    int** objects;
    int* candidate;
    int count;
    f32 nearestDist;

    nearestDist = lbl_803E5270;
    state = ((GameObject*)obj)->extra;
    if (state->linkedObj != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)state->linkedObj)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)state->linkedObj)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)state->linkedObj)->anim.localPosZ;
        ((GameObject*)obj)->anim.rotX = ((GameObject*)state->linkedObj)->anim.rotX;
        ObjGroup_FindNearestObjectForObject(NW_ICE_GROUP_ID, (u32)obj, &nearestDist);

        if (((GameObject*)state->linkedObj)->anim.alpha < ICE_FADE_ALPHA)
        {
            ObjHits_DisableObject((u32)obj);
            fn_80296D20(Obj_GetPlayerObject(), obj);
        }
        else
        {
            ObjHits_EnableObject((u32)obj);
        }

        if ((((GameObject*)state->linkedObj)->anim.alpha < ICE_FADE_ALPHA) || (nearestDist < lbl_803E5274))
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
        int** walker;
        objects = (int**)ObjGroup_GetObjects(NW_ANIMICE_GROUP_ID, &count);
        i = 0;
        walker = objects;
        setup = *(int**)&((GameObject*)obj)->anim.placementData;
        for (; i < count; i++)
        {
            candidate = *walker;
            if ((obj != candidate) &&
                (((NwIcePlacement*)setup)->pairId ==
                    *(u8*)((char*)*(int**)((char*)candidate + 0x4c) + 0x1b)))
            {
                state->linkedObj = objects[i];
                break;
            }
            walker++;
        }
    }
}

void nw_ice_init(int obj) { ObjGroup_AddObject(obj, NW_ICE_GROUP_ID); }
