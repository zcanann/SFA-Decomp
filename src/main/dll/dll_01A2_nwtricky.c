/* DLL 0x01A2 (nwtricky) — NW Tricky and mammoth objects [0x801CF78C-0x801CFB24). */
#include "main/dll/dim2conveyor.h"
#include "main/gameplay_runtime.h"


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



typedef struct NwTrickyState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
} NwTrickyState;


extern int** ObjGroup_GetObjects(int group, int* countOut);



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
void nw_animice_render(void);






/* 8b "li r3, N; blr" returners. */

/* ObjGroup_RemoveObject(x, N) wrappers. */


/* call(x, N) wrappers. */

void nw_tricky_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = (void*)nw_tricky_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

void nw_animice_init(int* obj);
