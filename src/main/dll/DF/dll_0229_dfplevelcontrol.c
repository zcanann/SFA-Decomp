/*
 * DragonRock Palace level controller (DLL 0x229; "DFP_LevelControl").
 * Drives the spell-puzzle level state: a per-mode countdown timer, RNG
 * seeding of the 6-entry puzzle solution table (lbl_80329848) when the
 * reset flag (lbl_803DC182) is raised, and gamebit-driven progression
 * (1504/1505/1507/1508/1589/3671) plus level unlocks and music triggers.
 */
#include "main/dll/dfp_types.h"
#include "main/main.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/lightmap.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"

#define DFPLEVELCONTROL_OBJGROUP 0x9

#define DFPLEVELCONTROL_OBJFLAG_HIDDEN 0x4000

extern u32 ObjMsg_SendToObject();
extern void fn_802960E8(void* playerObj, int p2);
extern s16 lbl_80329848[];
extern int dbstealerworm_stateHandlerB06();
extern int unlockLevel(s32 val, int idx, int flag);
extern void Music_Trigger(int id, int arg);

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

void fn_80204320(int obj)
{

    extern u8 lbl_803DC182;
    extern s16 lbl_80329848[];
    DfpLevelControlState* sub;
    void* player;

    sub = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (lbl_803DC182 != 0)
    {
        s16 i;
        lbl_80329848[6] = 0;
        lbl_80329848[7] = 0;
        lbl_80329848[8] = 0;
        for (i = 0; i < 6; i++)
        {
            lbl_80329848[i] = (s16)randomGetRange(1, 4);
        }
        GameBit_Set(1508, 0);
        sub->timer = 0;
        lbl_803DC182 = 0;
    }
    if (GameBit_Get(1507) == 0)
    {
        if (GameBit_Get(1504) != 0 && GameBit_Get(1505) != 0)
        {
            GameBit_Set(1507, 1);
        }
    }
    if (GameBit_Get(3671) == 0)
    {
        if (GameBit_Get(1589) != 0 && sub->sfxLatch == 0)
        {
            s16 i;
            Sfx_PlayFromObject(0, SFXTRIG_statue_wave);
            for (i = 0; i < 6; i++)
            {
                lbl_80329848[i] = (s16)randomGetRange(1, 4);
            }
            GameBit_Set(1508, 1);
            sub->sfxLatch = 1;
        }
        else if (GameBit_Get(1589) == 0 && sub->sfxLatch == 1)
        {
            sub->sfxLatch = 0;
            GameBit_Set(1508, 0);
        }
        if (GameBit_Get(1509) != 0)
        {
            sub->timer = 300;
            ObjMsg_SendToObject(player, 0x60005, obj, 1);
        }
    }
}

void dfplevelcontrol_render(void)
{
}

void dfplevelcontrol_hitDetect(void)
{
}

void dfplevelcontrol_release(void)
{
}

int dfplevelcontrol_getExtraSize(void) { return 0xc; }
int dfplevelcontrol_getObjectTypeId(void) { return 0x0; }

void dfplevelcontrol_free(int x) { extern u64 ObjGroup_RemoveObject(); ObjGroup_RemoveObject(x, DFPLEVELCONTROL_OBJGROUP); }

int dfplevelcontrol_SeqFn(int p1)
{

    DfpLevelControlState* p_b8 = ((GameObject*)p1)->extra;
    void* player = Obj_GetPlayerObject();
    s16 timer = p_b8->timer;
    if (timer > 0)
    {
        p_b8->timer -= (s16)timeDelta;
        fn_802960E8(player, 0x51e);
    }
    return 0;
}

void dfplevelcontrol_initialise(void)
{
    s16* p = lbl_80329848;
    p[0] = 1;
    p[1] = 2;
    p[2] = 3;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8] = 0;
}

void dfplevelcontrol_setScale(int unused, u8* out)
{
    int i;
    for (i = 0; (s16)i < 9; i += 3)
    {
        out[(s16)i] = lbl_80329848[i];
        out[(s16)(i + 1)] = lbl_80329848[i + 1];
        out[(s16)(i + 2)] = lbl_80329848[i + 2];
    }
}

void dfplevelcontrol_init(int obj, int param2)
{

    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    int mode;
    ObjGroup_AddObject(obj, DFPLEVELCONTROL_OBJGROUP);
    ((DfpFlags7*)&state->flags07)->b80 = GameBit_Get(0xd5d);
    ((DfpFlags7*)&state->flags07)->b40 = GameBit_Get(0xd59);
    ((DfpFlags7*)&state->flags07)->b20 = GameBit_Get(0xd5a);
    ((GameObject*)obj)->animEventCallback = (void*)dfplevelcontrol_SeqFn;
    state->mode = 1;
    mode = *(s16*)(param2 + 0x1a);
    if (mode != 0 && mode <= 2)
    {
        state->mode = mode;
    }
    (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    unlockLevel(0, 0, 1);
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | DFPLEVELCONTROL_OBJFLAG_HIDDEN;
    if (((GameObject*)obj)->anim.mapEventSlot == 0x15)
    {
        GameBit_Set(0xdce, 0);
    }
    if ((u32)GameBit_Get(0xdce) != 0)
    {
        Music_Trigger(MUSICTRIG_blizzard, 0);
        Music_Trigger(MUSICTRIG_trex_hit, 0);
    }
}

void dfplevelcontrol_update(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);

    extern void fn_80204098(int);
    extern void SCGameBitLatch_Update(void*, int, int, int, int, int);
    extern void SCGameBitLatch_UpdateInverted(void*, int, int, int, int, int);
    extern s16 lbl_803DC180;
    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    char* player;
    u8 b1;
    u8 b2;
    u8 b3;
    int mode;

    player = Obj_GetPlayerObject();
    b1 = GameBit_Get(0xd5d);
    b2 = GameBit_Get(0xd59);
    b3 = GameBit_Get(0xd5a);
    if ((b1 != 0 && ((u32)state->flags07 >> 7 & 1) == 0)
        || (b2 != 0 && ((u32)state->flags07 >> 6 & 1) == 0)
        || (b3 != 0 && ((u32)state->flags07 >> 5 & 1) == 0))
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    ((DfpFlags7*)&state->flags07)->b80 = b1;
    ((DfpFlags7*)&state->flags07)->b40 = b2;
    ((DfpFlags7*)&state->flags07)->b20 = b3;
    if (GameBit_Get(0x5e8) == 0 && GameBit_Get(0x5ee) != 0 && GameBit_Get(0x5ef) != 0)
    {
        GameBit_Set(0x5e8, 1);
    }
    coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
    mode = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        if (lbl_803DC180 != 0)
        {
            lbl_803DC180 -= (s16)timeDelta;
            if (lbl_803DC180 <= 0)
            {
                lbl_803DC180 = 0;
            }
        }
        fn_80204320(obj);
        break;
    case 2:
        fn_80204098(obj);
        break;
    case 3:
        break;
    }
    SCGameBitLatch_Update((void*)state->gameBitLatches, 2, -1, -1, 0xdce, 0x95);
    SCGameBitLatch_UpdateInverted((void*)state->gameBitLatches, 4, -1, -1, 0xdce, 0x37);
    SCGameBitLatch_UpdateInverted((void*)state->gameBitLatches, 1, -1, -1, 0xdce, 0xe4);
    GameBit_Set(0xdcf, 0);
}

void fn_80204098(int obj)
{
    extern void Sfx_PlayFromObject(u32 obj, u16 sfxId);
    extern u8 lbl_803DC183;
    extern s16 lbl_80329848[];
    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    void* player;
    s16 i;

    player = Obj_GetPlayerObject();
    if (lbl_803DC183 != 0)
    {
        GameBit_Set(0x2d, 1);
        GameBit_Set(0x1d7, 1);
        for (i = 0; i < 9; i++)
        {
            lbl_80329848[i] = (s16)randomGetRange(1, 4);
        }
        GameBit_Set(0x5e4, 0);
        state->timer = 0;
        lbl_803DC183 = 0;
    }
    if (GameBit_Get(0x5e3) == 0 && GameBit_Get(0x5e0) != 0 && GameBit_Get(0x5e1) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x5e3, 1);
    }
    if (GameBit_Get(0x792) == 0 && GameBit_Get(0xb8c) != 0 && GameBit_Get(0xb8c) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x792, 1);
    }
    if (GameBit_Get(0xe58) == 0)
    {
        if (GameBit_Get(0x635) != 0 && state->sfxLatch == 0)
        {
            Sfx_PlayFromObject(0, SFXfoot_wood_run_2);
            for (i = 0; i < 9; i++)
            {
                lbl_80329848[i] = (s16)randomGetRange(1, 4);
            }
            GameBit_Set(0x5e4, 1);
            state->sfxLatch = 1;
        }
        else
        {
            if (GameBit_Get(0x635) == 0 && state->sfxLatch == 1)
            {
                state->sfxLatch = 0;
                GameBit_Set(0x5e4, 0);
            }
        }
        if (GameBit_Get(0x5e5) != 0)
        {
            state->timer = 300;
            ObjMsg_SendToObject(player, 0x60005, obj, 0);
        }
    }
    if (GameBit_Get(0x7a1) != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 1);
        }
    }
}

int dbstealerworm_stateHandlerB06(int obj, int p2);
