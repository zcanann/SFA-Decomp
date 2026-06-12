/* === moved from main/dll/dim2conveyor.c [801CF78C-801CF7E8) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/dim2conveyor.h"
#include "main/gameplay_runtime.h"

extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objAudioFn_8006ef38();

extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);
extern void fn_8003A168(int obj, void* p);
extern void characterDoEyeAnims(int obj, void* p);
extern int cMenuGetSelectedItem(void);
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern void fn_801CDF94(int obj, void* state, int flag);
extern void fn_801CEE0C(int obj, void* state, void* objDef);
extern void fn_801CED2C(int obj, void* state, void* objDef);
extern void fn_801CEA14(int obj, void* state, void* objDef);
extern void fn_801CE2BC(int obj, void* state, void* objDef);
extern void Sfx_StopObjectChannel(void* obj, int channel);

extern u8 lbl_803267C0[];
extern u8 lbl_803267E8[];
extern u8 lbl_80326818[];
extern ObjHitReactEntry DAT_80327400;
extern ObjHitReactEntry DAT_80327414;
extern undefined4 DAT_80327468;
extern undefined4 DAT_80327498;
extern undefined4 DAT_803274f4;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern NwMammothPathControlInterface** gPathControlInterface;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern u32 lbl_803E5208;
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;
extern f32 lbl_803E524C;
extern f32 lbl_803E5254;
extern f32 lbl_803E5258;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;

#define gNwMammothNormalHitReactEntry DAT_80327400
#define gNwMammothHeavyHitReactEntry DAT_80327414
#define gNwMammothStateMoveIds DAT_80327468
#define gNwMammothStateMoveStepScales DAT_80327498
#define gNwMammothStateFlags DAT_803274f4

#define NW_MAMMOTH_STATE_FLAGS(table) ((u8 *)((table) + 0xf4))
#define NW_MAMMOTH_MOVE_IDS(table) ((s16 *)((table) + 0x68))
#define NW_MAMMOTH_MOVE_STEP_SCALES(table) ((f32 *)((table) + 0x98))
#define NW_MAMMOTH_HIT_REACT_ENTRIES(table) ((ObjHitReactEntry *)(table))
#define NW_MAMMOTH_HEAVY_HIT_REACT_ENTRIES(table) \
  ((ObjHitReactEntry *)((table) + sizeof(ObjHitReactEntry)))
#define NW_MAMMOTH_HIT_REACT_STEP_SCALE(state) ((f32 *)((state) + 0x50))
#define NW_MAMMOTH_HIT_REACT_STATE(state) ((state)[0x3d4])

enum NwMammothStateFlag
{
    NW_MAMMOTH_STATE_FLAG_PATH_CONTROL = 0x01,
    NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT = 0x02,
    NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT = 0x08,
    NW_MAMMOTH_STATE_FLAG_MENU_ACTION = 0x10,
    NW_MAMMOTH_STATE_FLAG_SOLID = 0x20,
};

enum NwMammothRuntimeFlag
{
    NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
    NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
    NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
    NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
    NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
    NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};

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
int nw_tricky_getExtraSize(void)
{
    return 8;
}

/*
 * --INFO--
 *
 * Function: nw_tricky_SeqFn
 * EN v1.0 Address: 0x801CF78C
 * EN v1.0 Size: 44b
 */
int nw_tricky_SeqFn(void)
{
    Sfx_StopObjectChannel(getTrickyObject(), 16);
    return 0;
}

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
void nw_tricky_free(int obj)
{
    (void)obj;
    GameBit_Set(0x4e4, 1);
}

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


extern undefined4 FUN_8000680c();
extern int FUN_80017a90();
extern int ObjGroup_FindNearestObjectForObject(int group, int* obj, f32* maxDistance);
extern int** ObjGroup_GetObjects(int group, int* countOut);
extern void ObjHits_DisableObject(int* obj);
extern void ObjHits_EnableObject(int* obj);
extern void fn_80296D20(int playerObj, int* obj);
extern undefined4 FUN_801ce244();

extern undefined4 DAT_80327428;
extern undefined4 DAT_80327458;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803e5ea0;
extern f32 lbl_803E5EE4;
extern f32 lbl_803E5EEC;
extern f32 lbl_803E5EF0;
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
void nw_tricky_update(int* obj)
{
    extern int* getTrickyObject(void); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    extern undefined4 GameBit_Set(int eventId, int value); /* #57 */
    int count;
    NwTrickyIds ids;
    char* state;
    int* tricky;
    int* player;
    int** objects;
    int** scan;
    int i;
    int* ip;
    int* found;
    f32 dPlayer;
    f32 t;

    state = ((GameObject*)obj)->extra;
    tricky = getTrickyObject();
    player = (int*)Obj_GetPlayerObject();
    ids = *(NwTrickyIds*)lbl_802C23E8;

    if (tricky == NULL)
    {
        return;
    }

    switch (*(u8*)state)
    {
    case 0:
        if (GameBit_Get(0xd11))
        {
            objects = ObjGroup_GetObjects(3, &count);
            for (i = 0, scan = objects; i < count; scan++, i++)
            {
                if (*(s16*)((char*)*scan + 0x46) == 0x13a)
                {
                    fn_8014C66C(*scan, player);
                }
            }
            GameBit_Set(0x4e4, 1);
            *(u8*)state = 1;
        }
        else
        {
            if (GameBit_Get(0x544))
            {
                if (!(*(u8 (**)(int*))(*(char**)*(char**)((char*)tricky + 0x68) + 0x40))(tricky))
                {
                    GameBit_Set(0x4e4, 0);
                    ((NwTrickyState*)state)->unk4 = lbl_803E5260;
                }

                for (i = 0, ip = ids.ids; i < 3; ip++, i++)
                {
                    found = ObjList_FindObjectById(*ip);
                    if (found != NULL && fn_8014C5D0(found) > lbl_803E5260)
                    {
                        (*(void (**)(int*, int, int*))(*(char**)*(char**)((char*)tricky + 0x68) + 0x34))(
                            tricky, 1, found);
                        break;
                    }
                }

                ((NwTrickyState*)state)->unk4 += timeDelta;
                t = ((NwTrickyState*)state)->unk4;
                if (t >= lbl_803E5264)
                {
                    ((NwTrickyState*)state)->unk4 = t - lbl_803E5264;
                    fn_80138920(tricky, 0x152, 0x1000);
                }
            }

            objects = ObjGroup_GetObjects(3, &count);
            for (i = 0, scan = objects; i < count; scan++, i++)
            {
                if (*(s16*)((char*)*scan + 0x46) == 0x13a)
                {
                    dPlayer = vec3f_distanceSquared(((NwObjPos*)*scan)->pos, ((NwObjPos*)player)->pos);
                    if (vec3f_distanceSquared(((NwObjPos*)*scan)->pos, ((NwObjPos*)tricky)->pos) < dPlayer)
                    {
                        fn_8014C66C(*scan, tricky);
                    }
                    else
                    {
                        fn_8014C66C(*scan, player);
                    }
                }
            }
        }
        break;
    case 1:
        if (!(*(u16*)((char*)tricky + 0xb0) & 0x1000))
        {
            ((NwTrickyState*)state)->unk4 += timeDelta;
        }
        if (GameBit_Get(0x4e3) == 1)
        {
            if ((*gMapEventInterface)->getProgressPtr()[0] >= 4)
            {
                GameBit_Set(0x4e3, 0xff);
            }
        }
        t = ((NwTrickyState*)state)->unk4;
        if (t >= lbl_803E5268)
        {
            ((NwTrickyState*)state)->unk4 = t - lbl_803E5268;
            if (GameBit_Get(0x4e3) == 0xff)
            {
                if ((*gMapEventInterface)->getProgressPtr()[0] < 4)
                {
                    GameBit_Set(0x4e3, 1);
                }
            }
        }
        break;
    }
}
#pragma opt_loop_invariants reset


/* Trivial 4b 0-arg blr leaves. */
void nw_animice_render(void)
{
}

void nw_animice_hitDetect(void)
{
}

void nw_animice_update(void)
{
}

void nw_animice_release(void)
{
}

void nw_animice_initialise(void)
{
}

void nw_ice_render(void)
{
}

/* 8b "li r3, N; blr" returners. */
int nw_animice_SeqFn(void) { return 0x0; }
int nw_animice_getExtraSize(void) { return 0x0; }
int nw_animice_getObjectTypeId(void) { return 0x0; }
int nw_ice_getExtraSize(void) { return 0x4; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
void nw_animice_free(int x) { ObjGroup_RemoveObject(x, 0x3d); }
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

void nw_tricky_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)nw_tricky_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

void nw_animice_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)nw_animice_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    ObjGroup_AddObject(obj, 0x3d);
}
