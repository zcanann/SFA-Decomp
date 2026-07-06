/*
 * nwtricky (DLL 0x1A2) - the SnowHorn Wastes controller for Tricky (the
 * player's companion) during the SnowHorn herding objective (map
 * 'nwastes', 0x0A).
 *
 * State 0: while the herd-start bit (0xd11) is clear, drive Tricky to
 * bark at / herd the SnowHorn herd objects (seqId 0x13a) toward whichever
 * of the player or Tricky is nearer, periodically issuing the bark
 * command; once 0xd11 is set the herding stops. State 1: meter Tricky's
 * energy via game bit 0x4e3 against the map-event Tricky-energy gauge.
 */
#include "main/gameplay_runtime.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"

#define NWTRICKY_OBJFLAG_PARENT_SLACK 0x1000
#define NWTRICKY_OBJFLAG_HIDDEN 0x4000
#define NWTRICKY_OBJFLAG_HITDETECT_DISABLED 0x2000
extern f32 timeDelta;
extern int** ObjGroup_GetObjects(int group, int* countOut);
extern void fn_8014C66C(int* obj, int* target);
extern f32 fn_8014C5D0(int* obj);
extern int* ObjList_FindObjectById(int objId);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void fn_80138920(int* obj, int a, int b);
extern const f32 lbl_803E5260;
extern f32 lbl_803E5264;
extern f32 lbl_803E5268;
extern int lbl_802C23E8[];

int nw_tricky_getExtraSize(void)
{
    return 8;
}

int nw_tricky_SeqFn(void)
{
    Sfx_StopObjectChannel((u32)getTrickyObject(), 16);
    return 0;
}

void nw_tricky_free(int obj)
{
    (void)obj;
    GameBit_Set(0x4e4, 1);
}

typedef struct NwTrickyState
{
    u8 pad0[0x4 - 0x0];
    f32 timer;
} NwTrickyState;

typedef struct NwTrickyIds
{
    int ids[3];
} NwTrickyIds;

typedef struct NwObjPos
{
    u8 pad[0x18];
    f32 worldPos[3];
} NwObjPos;

#pragma opt_loop_invariants off
void nw_tricky_update(int* obj)
{

    int count;
    NwTrickyIds ids;
    char* state;
    int* tricky;
    int* player;
    int** objects;
    int** scan;
    int* ip;
    int* found;
    f32 dPlayer;
    f32 timer;
    int i;

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
                if (((GameObject*)*scan)->anim.seqId == 0x13a)
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
                    ((NwTrickyState*)state)->timer = lbl_803E5260;
                }

                for (i = 0, ip = ids.ids; i < 3; i++, ip++)
                {
                    found = ObjList_FindObjectById(*ip);
                    if (found != NULL && fn_8014C5D0(found) > lbl_803E5260)
                    {
                        (*(void (**)(int*, int, int*))(*(char**)*(char**)((char*)tricky + 0x68) + 0x34))(
                            tricky, 1, found);
                        break;
                    }
                }

                ((NwTrickyState*)state)->timer += timeDelta;
                timer = ((NwTrickyState*)state)->timer;
                if (timer >= lbl_803E5264)
                {
                    ((NwTrickyState*)state)->timer = timer - lbl_803E5264;
                    fn_80138920(tricky, 0x152, 0x1000);
                }
            }

            objects = ObjGroup_GetObjects(3, &count);
            for (i = 0, scan = objects; i < count; scan++, i++)
            {
                if (((GameObject*)*scan)->anim.seqId == 0x13a)
                {
                    dPlayer = vec3f_distanceSquared(((NwObjPos*)*scan)->worldPos, ((NwObjPos*)player)->worldPos);
                    if (vec3f_distanceSquared(((NwObjPos*)*scan)->worldPos, ((NwObjPos*)tricky)->worldPos) < dPlayer)
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
        if (!(((GameObject*)tricky)->objectFlags & NWTRICKY_OBJFLAG_PARENT_SLACK))
        {
            ((NwTrickyState*)state)->timer += timeDelta;
        }
        if (GameBit_Get(0x4e3) == 1)
        {
            if ((*gMapEventInterface)->getTrickyEnergy()[0] >= 4)
            {
                GameBit_Set(0x4e3, 0xff);
            }
        }
        timer = ((NwTrickyState*)state)->timer;
        if (timer >= lbl_803E5268)
        {
            ((NwTrickyState*)state)->timer = timer - lbl_803E5268;
            if (GameBit_Get(0x4e3) == 0xff)
            {
                if ((*gMapEventInterface)->getTrickyEnergy()[0] < 4)
                {
                    GameBit_Set(0x4e3, 1);
                }
            }
        }
        break;
    }
}
#pragma opt_loop_invariants reset

void nw_tricky_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = nw_tricky_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (NWTRICKY_OBJFLAG_HIDDEN | NWTRICKY_OBJFLAG_HITDETECT_DISABLED));
}
