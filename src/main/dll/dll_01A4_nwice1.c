/* === moved from main/dll/dim2conveyor.c [801CF78C-801CF7E8) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/dim2conveyor.h"
#include "main/gameplay_runtime.h"

extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjGroup_RemoveObject();

extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void Sfx_StopObjectChannel(void* obj, int channel);

extern f32 timeDelta;





/*
 * --INFO--
 *
 * Function: nw_mammoth_update
 * EN v1.0 Address: 0x801CF0AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF2E0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: nw_mammoth_init
 * EN v1.0 Address: 0x801CF4F0
 * EN v1.0 Size: 668b
 */


/*
 * --INFO--
 *
 * Function: FUN_801cf0b4
 * EN v1.0 Address: 0x801CF0B4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CF570
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: nw_tricky_getExtraSize
 * EN v1.0 Address: 0x801CF7B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int nw_tricky_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: nw_tricky_SeqFn
 * EN v1.0 Address: 0x801CF78C
 * EN v1.0 Size: 44b
 */
int nw_tricky_SeqFn(void);

/*
 * --INFO--
 *
 * Function: FUN_801cf108
 * EN v1.0 Address: 0x801CF108
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801CF5C4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


#pragma scheduling off
#pragma peephole off
void nw_tricky_free(int obj);

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/creator1D6.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"

typedef struct NwIcePlacement
{
    u8 pad0[0x1B - 0x0];
    u8 unk1B;
    u8 pad1C[0x20 - 0x1C];
} NwIcePlacement;


typedef struct NwTrickyState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
} NwTrickyState;


extern int ObjGroup_FindNearestObjectForObject(int group, int* obj, f32* maxDistance);
extern int** ObjGroup_GetObjects(int group, int* countOut);
extern void ObjHits_DisableObject(int* obj);
extern void ObjHits_EnableObject(int* obj);
extern void fn_80296D20(int playerObj, int* obj);

extern f32 lbl_803E5270;
extern f32 lbl_803E5274;

typedef struct NwIceState
{
    int* linkedObj;
} NwIceState;

extern void fn_8014C66C(int* obj, int* target);
extern f32 fn_8014C5D0(int* obj);
extern int* ObjList_FindObjectById(int objId);
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern void fn_80138920(int* obj, int a, int b);
extern const f32 lbl_803E5260;
extern f32 lbl_803E5264;
extern f32 lbl_803E5268;
extern int lbl_802C23E8[];

typedef struct NwTrickyIds
{
    int ids[3];
} NwTrickyIds;

typedef struct NwObjPos
{
    u8 pad[0x18];
    f32 pos[3];
} NwObjPos;

/*
 * --INFO--
 *
 * Function: nw_tricky_update
 * EN v1.0 Address: 0x801CF7E8
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x801CFAC0
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma opt_loop_invariants off
void nw_tricky_update(int* obj);
#pragma opt_loop_invariants reset


/* Trivial 4b 0-arg blr leaves. */
void nw_animice_render(void);

void nw_animice_hitDetect(void);

void nw_animice_update(void);

void nw_animice_release(void);

void nw_animice_initialise(void);

void nw_ice_render(void)
{
}

/* 8b "li r3, N; blr" returners. */
int nw_animice_SeqFn(void);
int nw_animice_getExtraSize(void);
int nw_animice_getObjectTypeId(void);
int nw_ice_getExtraSize(void) { return 0x4; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void nw_animice_free(int x);
void nw_ice_free(int x) { ObjGroup_RemoveObject(x, 0x3c); }

void nw_ice_update(int* obj)
{
    extern int Obj_GetPlayerObject(void); /* #57 */
    NwIceState* state;
    int* setup;
    int i;
    int** scan;
    int** objects;
    int* candidate;
    int count;
    f32 nearestDist;

    nearestDist = lbl_803E5270;
    state = ((GameObject*)obj)->extra;
    if (state->linkedObj != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)state->linkedObj + 0xc);
        ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)state->linkedObj + 0x10);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)state->linkedObj + 0x14);
        *(s16*)obj = *(s16*)state->linkedObj;
        ObjGroup_FindNearestObjectForObject(0x3c, obj, &nearestDist);

        if (((GameObject*)state->linkedObj)->anim.alpha < 0xc0)
        {
            ObjHits_DisableObject(obj);
            fn_80296D20(Obj_GetPlayerObject(), obj);
        }
        else
        {
            ObjHits_EnableObject(obj);
        }

        if ((((GameObject*)state->linkedObj)->anim.alpha < 0xc0) || (nearestDist < lbl_803E5274))
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
        objects = ObjGroup_GetObjects(0x3d, &count);
        setup = *(int**)&((GameObject*)obj)->anim.placementData;
        scan = objects;
        for (i = 0; i < count; scan++, i++)
        {
            candidate = *scan;
            if ((obj != candidate) &&
                (((NwIcePlacement*)setup)->unk1B ==
                    *(u8*)((char*)*(int**)((char*)candidate + 0x4c) + 0x1b)))
            {
                state->linkedObj = objects[i];
                break;
            }
        }
    }
}

/* call(x, N) wrappers. */
void nw_ice_init(int x) { ObjGroup_AddObject(x, 0x3c); }

void nw_tricky_init(int* obj);

void nw_animice_init(int* obj);
