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
#include "main/gamebit_ids.h"
#include "main/frame_timing.h"
#include "main/dll/NW/dll_01A2_nwtricky.h"

#define NWTRICKY_OBJFLAG_PARENT_SLACK       0x1000
#define NWTRICKY_OBJFLAG_HIDDEN             0x4000
#define NWTRICKY_OBJFLAG_HITDETECT_DISABLED 0x2000

/* anim.seqId of the SnowHorn herd objects Tricky herds (docblock: "the
 * SnowHorn herd objects (seqId 0x13a)"). */
#define NWTRICKY_SNOWHORN_HERD_SEQID 0x13a

extern int** ObjGroup_GetObjects(int group, int* countOut);
extern void fn_8014C66C(int* obj, int* target);
extern f32 enemy_getHealthFraction(int* obj);
extern int* ObjList_FindObjectById(int objId);
extern f32 vec3f_distanceSquared(f32* a, f32* b);
extern void fn_80138920(int* obj, int a, int b);
extern const f32 lbl_803E5260;
extern f32 lbl_803E5264;
extern f32 lbl_803E5268;
extern int lbl_802C23E8[];

int NW_tricky_getExtraSize(void)
{
    return 8;
}

int NW_tricky_SeqFn(void)
{
    Sfx_StopObjectChannel((u32)getTrickyObject(), 16);
    return 0;
}

void NW_tricky_free(int obj)
{
    (void)obj;
    mainSetBits(GAMEBIT_Tricky_Usable, 1);
}

#pragma opt_loop_invariants off
void NW_tricky_update(int* obj)
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
        if (mainGetBit(0xd11))
        {
            objects = ObjGroup_GetObjects(3, &count);
            for (i = 0, scan = objects; i < count; scan++, i++)
            {
                if (((GameObject*)*scan)->anim.seqId == NWTRICKY_SNOWHORN_HERD_SEQID)
                {
                    fn_8014C66C(*scan, player);
                }
            }
            mainSetBits(GAMEBIT_Tricky_Usable, 1);
            *(u8*)state = 1;
        }
        else
        {
            if (mainGetBit(GAMEBIT_ITEM_TrickyStayFind_Got))
            {
                if (!(*(u8(**)(int*))(*(char**)*(char**)((char*)tricky + 0x68) + 0x40))(tricky))
                {
                    mainSetBits(GAMEBIT_Tricky_Usable, 0);
                    ((NwTrickyState*)state)->timer = lbl_803E5260;
                }

                for (i = 0, ip = ids.ids; i < 3; i++, ip++)
                {
                    found = ObjList_FindObjectById(*ip);
                    if (found != NULL && enemy_getHealthFraction(found) > lbl_803E5260)
                    {
                        (*(void (**)(int*, int, int*))(*(char**)*(char**)((char*)tricky + 0x68) + 0x34))(tricky, 1,
                                                                                                         found);
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
                if (((GameObject*)*scan)->anim.seqId == NWTRICKY_SNOWHORN_HERD_SEQID)
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
        if (mainGetBit(GAMEBIT_TrickyTalk) == 1)
        {
            if ((*gMapEventInterface)->getTrickyEnergy()[0] >= 4)
            {
                mainSetBits(GAMEBIT_TrickyTalk, 0xff);
            }
        }
        timer = ((NwTrickyState*)state)->timer;
        if (timer >= lbl_803E5268)
        {
            ((NwTrickyState*)state)->timer = timer - lbl_803E5268;
            if (mainGetBit(GAMEBIT_TrickyTalk) == 0xff)
            {
                if ((*gMapEventInterface)->getTrickyEnergy()[0] < 4)
                {
                    mainSetBits(GAMEBIT_TrickyTalk, 1);
                }
            }
        }
        break;
    }
}
#pragma opt_loop_invariants reset

void NW_tricky_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = NW_tricky_SeqFn;
    ((GameObject*)obj)->objectFlags =
        (u16)(((GameObject*)obj)->objectFlags | (NWTRICKY_OBJFLAG_HIDDEN | NWTRICKY_OBJFLAG_HITDETECT_DISABLED));
}
