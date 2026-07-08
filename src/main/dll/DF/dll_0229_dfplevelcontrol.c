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
#include "main/gamebit_ids.h"
#include "main/objlib.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/lightmap.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx.h"

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

#define DFPLEVELCONTROL_OBJGROUP 0x9

#define DFPLEVELCONTROL_OBJFLAG_HIDDEN 0x4000

/* repels the player away from this object and applies status damage (arg = status type) */
#define DFPLEVELCONTROL_MSG_PLAYER_HIT 0x60005

extern s16 lbl_80329848[];
extern u8 lbl_803DC183;
extern u8 lbl_803DC182;
extern s16 lbl_803DC180;
extern u32 ObjMsg_SendToObject();
extern void fn_802960E8(void* playerObj, int p2);
extern int dbstealerworm_stateHandlerB06();
int dbstealerworm_stateHandlerB06(int obj, int p2);
extern int unlockLevel(s32 val, int idx, int flag);
extern void Music_Trigger(int id, int arg);
extern void fn_80204098(int);
extern void SCGameBitLatch_Update(void*, int, int, int, int, int);
extern void SCGameBitLatch_UpdateInverted(void*, int, int, int, int, int);

void fn_80204098(int obj)
{
    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    void* player;
    s16 i;

    player = Obj_GetPlayerObject();
    if (lbl_803DC183 != 0)
    {
        mainSetBits(GAMEBIT_STAFF_ABILITY_FIRE_BLASTER, 1);
        mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);
        for (i = 0; i < 9; i++)
        {
            lbl_80329848[i] = (s16)randomGetRange(1, 4);
        }
        mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
        state->timer = 0;
        lbl_803DC183 = 0;
    }
    if (mainGetBit(0x5e3) == 0 && mainGetBit(0x5e0) != 0 && mainGetBit(0x5e1) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_espk2_c);
        mainSetBits(0x5e3, 1);
    }
    if (mainGetBit(0x792) == 0 && mainGetBit(0xb8c) != 0 && mainGetBit(0xb8c) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_espk2_c);
        mainSetBits(0x792, 1);
    }
    if (mainGetBit(0xe58) == 0)
    {
        if (mainGetBit(0x635) != 0 && state->sfxLatch == 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_1c4);
            for (i = 0; i < 9; i++)
            {
                lbl_80329848[i] = (s16)randomGetRange(1, 4);
            }
            mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 1);
            state->sfxLatch = 1;
        }
        else
        {
            if (mainGetBit(0x635) == 0 && state->sfxLatch == 1)
            {
                state->sfxLatch = 0;
                mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
            }
        }
        if (mainGetBit(0x5e5) != 0)
        {
            state->timer = 300;
            ObjMsg_SendToObject(player, DFPLEVELCONTROL_MSG_PLAYER_HIT, obj, 0);
        }
    }
    if (mainGetBit(0x7a1) != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 1);
        }
    }
}

void fn_80204320(int obj)
{
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
        mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
        sub->timer = 0;
        lbl_803DC182 = 0;
    }
    if (mainGetBit(1507) == 0)
    {
        if (mainGetBit(1504) != 0 && mainGetBit(1505) != 0)
        {
            mainSetBits(1507, 1);
        }
    }
    if (mainGetBit(3671) == 0)
    {
        if (mainGetBit(1589) != 0 && sub->sfxLatch == 0)
        {
            s16 i;
            Sfx_PlayFromObject(0, SFXTRIG_statue_wave);
            for (i = 0; i < 6; i++)
            {
                lbl_80329848[i] = (s16)randomGetRange(1, 4);
            }
            mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 1);
            sub->sfxLatch = 1;
        }
        else if (mainGetBit(1589) == 0 && sub->sfxLatch == 1)
        {
            sub->sfxLatch = 0;
            mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
        }
        if (mainGetBit(1509) != 0)
        {
            sub->timer = 300;
            ObjMsg_SendToObject(player, DFPLEVELCONTROL_MSG_PLAYER_HIT, obj, 1);
        }
    }
}

int DFP_LevelControl_SeqFn(int p1)
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

void DFP_LevelControl_setScale(int unused, u8* out)
{
    int i;
    for (i = 0; (s16)i < 9; i += 3)
    {
        out[(s16)i] = lbl_80329848[i];
        out[(s16)(i + 1)] = lbl_80329848[i + 1];
        out[(s16)(i + 2)] = lbl_80329848[i + 2];
    }
}

int DFP_LevelControl_getExtraSize(void)
{
    return 0xc;
}
int DFP_LevelControl_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_LevelControl_free(int obj)
{
    extern u64 ObjGroup_RemoveObject();
    ObjGroup_RemoveObject(obj, DFPLEVELCONTROL_OBJGROUP);
}

void DFP_LevelControl_render(void)
{
}

void DFP_LevelControl_hitDetect(void)
{
}

void DFP_LevelControl_update(int obj)
{
    extern void* Obj_GetPlayerObject(void);

    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    char* player;
    u8 b1;
    u8 b2;
    u8 b3;
    int mode;

    player = Obj_GetPlayerObject();
    b1 = mainGetBit(0xd5d);
    b2 = mainGetBit(0xd59);
    b3 = mainGetBit(0xd5a);
    if ((b1 != 0 && ((u32)state->flags07 >> 7 & 1) == 0) || (b2 != 0 && ((u32)state->flags07 >> 6 & 1) == 0) ||
        (b3 != 0 && ((u32)state->flags07 >> 5 & 1) == 0))
    {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }
    ((DfpFlags7*)&state->flags07)->b80 = b1;
    ((DfpFlags7*)&state->flags07)->b40 = b2;
    ((DfpFlags7*)&state->flags07)->b20 = b3;
    if (mainGetBit(0x5e8) == 0 && mainGetBit(0x5ee) != 0 && mainGetBit(0x5ef) != 0)
    {
        mainSetBits(0x5e8, 1);
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
    mainSetBits(0xdcf, 0);
}

void DFP_LevelControl_init(int obj, int param2)
{

    DfpLevelControlState* state = ((GameObject*)obj)->extra;
    int mode;
    ObjGroup_AddObject(obj, DFPLEVELCONTROL_OBJGROUP);
    ((DfpFlags7*)&state->flags07)->b80 = mainGetBit(0xd5d);
    ((DfpFlags7*)&state->flags07)->b40 = mainGetBit(0xd59);
    ((DfpFlags7*)&state->flags07)->b20 = mainGetBit(0xd5a);
    ((GameObject*)obj)->animEventCallback = (void*)DFP_LevelControl_SeqFn;
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
        mainSetBits(0xdce, 0);
    }
    if ((u32)mainGetBit(0xdce) != 0)
    {
        Music_Trigger(MUSICTRIG_blizzard, 0);
        Music_Trigger(MUSICTRIG_trex_hit, 0);
    }
}

void DFP_LevelControl_release(void)
{
}

void DFP_LevelControl_initialise(void)
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
